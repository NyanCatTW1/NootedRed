//  Copyright © 2022-2023 ChefKiss Inc. Licensed under the Thou Shalt Not Profit License version 1.0. See LICENSE for
//  details.

#ifndef kern_nred_hpp
#define kern_nred_hpp
#include "kern_amd.hpp"
#include "kern_fw.hpp"
#include "kern_vbios.hpp"
#include <Headers/kern_iokit.hpp>
#include <IOKit/acpi/IOACPIPlatformExpert.h>
#include <IOKit/graphics/IOFramebuffer.h>
#include <IOKit/pci/IOPCIDevice.h>

class EXPORT PRODUCT_NAME : public IOService {
    OSDeclareDefaultStructors(PRODUCT_NAME);

    public:
    IOService *probe(IOService *provider, SInt32 *score) override;
    bool start(IOService *provider) override;
};

enum struct ChipType : uint32_t {
    Raven = 0,
    Picasso,
    Raven2,
    Renoir,
    GreenSardine,
    Unknown,
};

// Hack
class AppleACPIPlatformExpert : IOACPIPlatformExpert {
    friend class NRed;
};

// https://elixir.bootlin.com/linux/latest/source/drivers/gpu/drm/amd/amdgpu/amdgpu_bios.c#L49
static bool checkAtomBios(const uint8_t *bios, size_t size) {
    uint16_t tmp, bios_header_start;

    if (size < 0x49) {
        DBGLOG("nred", "VBIOS size is invalid");
        return false;
    }

    if (bios[0] != 0x55 || bios[1] != 0xAA) {
        DBGLOG("nred", "VBIOS signature <%x %x> is invalid", bios[0], bios[1]);
        return false;
    }

    bios_header_start = bios[0x48] | (bios[0x49] << 8);
    if (!bios_header_start) {
        DBGLOG("nred", "Unable to locate VBIOS header");
        return false;
    }

    tmp = bios_header_start + 4;
    if (size < tmp) {
        DBGLOG("nred", "BIOS header is broken");
        return false;
    }

    if (!memcmp(bios + tmp, "ATOM", 4) || !memcmp(bios + tmp, "MOTA", 4)) {
        DBGLOG("nred", "ATOMBIOS detected");
        return true;
    }

    return false;
}

/**
 *  Console info structure, taken from osfmk/console/video_console.h
 *  Last updated from XNU 4570.1.46.
 */
struct vc_info {
    unsigned int v_height; /* pixels */
    unsigned int v_width;  /* pixels */
    unsigned int v_depth;
    unsigned int v_rowbytes;
    unsigned long v_baseaddr;
    unsigned int v_type;
    char v_name[32];
    uint64_t v_physaddr;
    unsigned int v_rows;         /* characters */
    unsigned int v_columns;      /* characters */
    unsigned int v_rowscanbytes; /* Actualy number of bytes used for display per row*/
    unsigned int v_scale;
    unsigned int v_rotate;
    unsigned int v_reserved[3];
};

// This is a hack to let us access protected properties.
struct FramebufferViewer : public IOFramebuffer {
    static IOMemoryMap *&getVRAMMap(IOFramebuffer *fb) { return static_cast<FramebufferViewer *>(fb)->fVramMap; }
};

class NRed {
    friend class X6000FB;
    friend class X5000HWLibs;
    friend class X6000;
    friend class X5000;

    public:
    static NRed *callback;

    void init();
    void processPatcher(KernelPatcher &patcher);
    void setRMMIOIfNecessary();
    void processKext(KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size);

    private:
    static const char *getChipName() {
        PANIC_COND(callback->chipType == ChipType::Unknown, "nred", "Unknown chip type");
        static const char *chipNames[] = {"raven", "raven2", "picasso", "renoir", "green_sardine"};
        return chipNames[static_cast<int>(callback->chipType)];
    }

    bool getVBIOSFromVFCT(IOPCIDevice *obj) {
        DBGLOG("nred", "Fetching VBIOS from VFCT table");
        auto *expert = reinterpret_cast<AppleACPIPlatformExpert *>(obj->getPlatform());
        PANIC_COND(!expert, "nred", "Failed to get AppleACPIPlatformExpert");

        auto *vfctData = expert->getACPITableData("VFCT", 0);
        if (!vfctData) {
            DBGLOG("nred", "No VFCT from AppleACPIPlatformExpert");
            return false;
        }

        auto *vfct = static_cast<const VFCT *>(vfctData->getBytesNoCopy());
        PANIC_COND(!vfct, "nred", "VFCT OSData::getBytesNoCopy returned null");

        auto offset = vfct->vbiosImageOffset;

        while (offset < vfctData->getLength()) {
            auto *vHdr =
                static_cast<const GOPVideoBIOSHeader *>(vfctData->getBytesNoCopy(offset, sizeof(GOPVideoBIOSHeader)));
            if (!vHdr) {
                DBGLOG("nred", "VFCT header out of bounds");
                return false;
            }

            auto *vContent = static_cast<const uint8_t *>(
                vfctData->getBytesNoCopy(offset + sizeof(GOPVideoBIOSHeader), vHdr->imageLength));
            if (!vContent) {
                DBGLOG("nred", "VFCT VBIOS image out of bounds");
                return false;
            }

            offset += sizeof(GOPVideoBIOSHeader) + vHdr->imageLength;

            if (vHdr->imageLength && vHdr->pciBus == obj->getBusNumber() && vHdr->pciDevice == obj->getDeviceNumber() &&
                vHdr->pciFunction == obj->getFunctionNumber() &&
                vHdr->vendorID == obj->configRead16(kIOPCIConfigVendorID) &&
                vHdr->deviceID == obj->configRead16(kIOPCIConfigDeviceID)) {
                if (!checkAtomBios(vContent, vHdr->imageLength)) {
                    DBGLOG("nred", "VFCT VBIOS is not an ATOMBIOS");
                    return false;
                }
                this->vbiosData = OSData::withBytes(vContent, vHdr->imageLength);
                PANIC_COND(!this->vbiosData, "nred", "VFCT OSData::withBytes failed");
                obj->setProperty("ATY,bin_image", this->vbiosData);
                return true;
            }
        }

        return false;
    }

    bool getVBIOSFromVRAM(IOPCIDevice *provider) {
        auto *bar0 = provider->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
        if (!bar0 || !bar0->getLength()) {
            DBGLOG("nred", "FB BAR not enabled");
            OSSafeReleaseNULL(bar0);
            return false;
        }
        auto *fb = reinterpret_cast<const uint8_t *>(bar0->getVirtualAddress());
        uint32_t size = 256 * 1024;    // ???
        if (!checkAtomBios(fb, size)) {
            DBGLOG("nred", "VRAM VBIOS is not an ATOMBIOS");
            bar0->release();
            return false;
        }
        this->vbiosData = OSData::withBytes(fb, size);
        PANIC_COND(!this->vbiosData, "nred", "VRAM OSData::withBytes failed");
        provider->setProperty("ATY,bin_image", this->vbiosData);
        bar0->release();
        return true;
    }

    uint32_t readReg32(uint32_t reg) {
        if (reg * 4 < this->rmmio->getLength()) {
            return this->rmmioPtr[reg];
        } else {
            this->rmmioPtr[mmPCIE_INDEX2] = reg;
            return this->rmmioPtr[mmPCIE_DATA2];
        }
    }

    void writeReg32(uint32_t reg, uint32_t val) {
        if (reg * 4 < this->rmmio->getLength()) {
            this->rmmioPtr[reg] = val;
        } else {
            this->rmmioPtr[mmPCIE_INDEX2] = reg;
            this->rmmioPtr[mmPCIE_DATA2] = val;
        }
    }

    static void sleepLoop(const char *eventDesc, int32_t msLeft = 0) {
        while (msLeft > 0) {
            DBGLOG("nred", "%s in %d ms...", eventDesc, msLeft);
            IOSleep(200);
            msLeft -= 200;
        }
    }

    template<typename T>
    T *getVBIOSDataTable(uint32_t index) {
        auto *vbios = static_cast<const uint8_t *>(this->vbiosData->getBytesNoCopy());
        auto base = *reinterpret_cast<const uint16_t *>(vbios + ATOM_ROM_TABLE_PTR);
        auto dataTable = *reinterpret_cast<const uint16_t *>(vbios + base + ATOM_ROM_DATA_PTR);
        auto *mdt = reinterpret_cast<const uint16_t *>(vbios + dataTable + 4);
        auto offset = mdt[index];
        return offset ? reinterpret_cast<T *>(const_cast<uint8_t *>(vbios) + offset) : nullptr;
    }

    OSData *vbiosData {nullptr};
    ChipType chipType = ChipType::Unknown;
    uint64_t vramStart {0};
    uint64_t vramEnd {0};
    uint64_t fbOffset {0};
    IOMemoryMap *rmmio {nullptr};
    volatile uint32_t *rmmioPtr {nullptr};
    uint32_t deviceId {0};
    uint16_t enumeratedRevision {0};
    uint16_t revision {0};
    uint32_t pciRevision {0};
    IOPCIDevice *iGPU {nullptr};
    OSMetaClass *metaClassMap[4][2] = {{nullptr}};
    mach_vm_address_t orgSafeMetaCast {0};
    mach_vm_address_t orgApplePanelSetDisplay {0};
    mach_vm_address_t orgCsValidatePage {0};
    vc_info consoleVinfo {};
    bool gotConsoleVinfo {false};
    uint8_t *gIOFBVerboseBootPtr {nullptr};
    mach_vm_address_t orgFramebufferInit {0};

    static void panic_print_symbol_name(vm_address_t search);
    mach_vm_address_t _mh_execute_header {};
    static void panic_print_kmod_symbol_name(vm_address_t search);
    mach_vm_address_t orggLoadedKextSummaries = {};
    static void i386_backtrace();

    static OSMetaClassBase *wrapSafeMetaCast(const OSMetaClassBase *anObject, const OSMetaClass *toMeta);
    static size_t wrapFunctionReturnZero();
    static bool wrapApplePanelSetDisplay(IOService *that, IODisplay *display);
    static void csValidatePage(vnode *vp, memory_object_t pager, memory_object_offset_t page_offset, const void *data,
        int *validated_p, int *tainted_p, int *nx_p);
    static void wrapFramebufferInit(IOFramebuffer *fb);
};

#endif /* AMDRadeonX6000_hpp */
