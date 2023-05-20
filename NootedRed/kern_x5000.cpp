//  Copyright © 2022-2023 ChefKiss Inc. Licensed under the Thou Shalt Not Profit License version 1.0. See LICENSE for
//  details.

#include "kern_x5000.hpp"
#include "kern_nred.hpp"
#include "kern_patches.hpp"
#include "kern_x6000.hpp"
#include <Headers/kern_api.hpp>

static const char *pathRadeonX5000 = "/System/Library/Extensions/AMDRadeonX5000.kext/Contents/MacOS/AMDRadeonX5000";

static KernelPatcher::KextInfo kextRadeonX5000 {"com.apple.kext.AMDRadeonX5000", &pathRadeonX5000, 1, {}, {},
    KernelPatcher::KextInfo::Unloaded};

X5000 *X5000::callback = nullptr;

void X5000::init() {
    callback = this;
    lilu.onKextLoadForce(&kextRadeonX5000);
}

bool X5000::processKext(KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
    if (kextRadeonX5000.loadIndex == index) {
        NRed::callback->setRMMIOIfNecessary();

        void *startHWEngines = nullptr;

        KernelPatcher::SolveRequest solveRequests[] = {
            {"__ZN31AMDRadeonX5000_AMDGFX9PM4EngineC1Ev", this->orgGFX9PM4EngineConstructor},
            {"__ZN32AMDRadeonX5000_AMDGFX9SDMAEngineC1Ev", this->orgGFX9SDMAEngineConstructor},
            {"__ZN39AMDRadeonX5000_AMDAccelSharedUserClient5startEP9IOService", this->orgAccelSharedUCStart},
            {"__ZN39AMDRadeonX5000_AMDAccelSharedUserClient4stopEP9IOService", this->orgAccelSharedUCStop},
            {"__ZN35AMDRadeonX5000_AMDAccelVideoContext10gMetaClassE", NRed::callback->metaClassMap[0][0]},
            {"__ZN37AMDRadeonX5000_AMDAccelDisplayMachine10gMetaClassE", NRed::callback->metaClassMap[1][0]},
            {"__ZN34AMDRadeonX5000_AMDAccelDisplayPipe10gMetaClassE", NRed::callback->metaClassMap[2][0]},
            {"__ZN30AMDRadeonX5000_AMDAccelChannel10gMetaClassE", NRed::callback->metaClassMap[3][1]},
            {"__ZN30AMDRadeonX5000_AMDGFX9Hardware32setupAndInitializeHWCapabilitiesEv",
                this->orgSetupAndInitializeHWCapabilities},
            {"__ZN26AMDRadeonX5000_AMDHardware14startHWEnginesEv", startHWEngines},
            {"__ZN26AMDRadeonX5000_AMDHardware17dumpASICHangStateEb", this->orgDumpASICHangState},
            {"__ZN29AMDRadeonX5000_AMDHWVMContext7getVMPTEP12AMD_VMPT_CTL15eAMD_VMPT_LEVELyPyS3_S3_j",
                this->orgGetVMPT},
        };
        PANIC_COND(!patcher.solveMultiple(index, solveRequests, address, size), "x5000", "Failed to resolve symbols");

        uint32_t *orgChannelTypes = patcher.solveSymbol<uint32_t *>(index,
            "__ZZN37AMDRadeonX5000_AMDGraphicsAccelerator19createAccelChannelsEbE12channelTypes", address, size);
        if (!orgChannelTypes) {
            size_t offset = 0;
            PANIC_COND(!patcher.findPattern(kChannelTypesOriginal, nullptr, arrsize(kChannelTypesOriginal),
                           reinterpret_cast<void *>(address), size, &offset),
                "x5000", "Failed to find createAccelChannels::channelTypes");
            orgChannelTypes = reinterpret_cast<uint32_t *>(address + offset);
        }

        KernelPatcher::RouteRequest requests[] = {
            {"__ZN32AMDRadeonX5000_AMDVega10Hardware17allocateHWEnginesEv", wrapAllocateHWEngines},
            {"__ZN32AMDRadeonX5000_AMDVega10Hardware32setupAndInitializeHWCapabilitiesEv",
                wrapSetupAndInitializeHWCapabilities},
            {"__ZN26AMDRadeonX5000_AMDHardware12getHWChannelE20_eAMD_HW_ENGINE_TYPE18_eAMD_HW_RING_TYPE",
                wrapGetHWChannel, this->orgGetHWChannel},
            {"__ZN30AMDRadeonX5000_AMDGFX9Hardware20initializeFamilyTypeEv", wrapInitializeFamilyType},
            {"__ZN30AMDRadeonX5000_AMDGFX9Hardware20allocateAMDHWDisplayEv", wrapAllocateAMDHWDisplay},
            {"__ZN41AMDRadeonX5000_AMDGFX9GraphicsAccelerator15newVideoContextEv", wrapNewVideoContext},
            {"__ZN31AMDRadeonX5000_IAMDSMLInterface18createSMLInterfaceEj", wrapCreateSMLInterface},
            {"__ZN26AMDRadeonX5000_AMDHWMemory17adjustVRAMAddressEy", wrapAdjustVRAMAddress,
                this->orgAdjustVRAMAddress},
            {"__ZN37AMDRadeonX5000_AMDGraphicsAccelerator9newSharedEv", wrapNewShared},
            {"__ZN37AMDRadeonX5000_AMDGraphicsAccelerator19newSharedUserClientEv", wrapNewSharedUserClient},
            {"__ZN30AMDRadeonX5000_AMDGFX9Hardware25allocateAMDHWAlignManagerEv", wrapAllocateAMDHWAlignManager,
                this->orgAllocateAMDHWAlignManager},
            {"__ZN43AMDRadeonX5000_AMDVega10GraphicsAccelerator13getDeviceTypeEP11IOPCIDevice", wrapGetDeviceType},
            {"__ZN24AMDRadeonX5000_AMDRTRing9writeTailEv", wrapWriteTail, orgWriteTail},
            {"__ZN34AMDRadeonX5000_AMDAccelDisplayPipe20writeDiagnosisReportERPcRj", wrapDispPipeWriteDiagnosisReport,
                orgDispPipeWriteDiagnosisReport},
            {"__ZN30AMDRadeonX5000_AMDGFX9Hardware20writeASICHangLogInfoEPPv", wrapWriteASICHangLogInfo,
                orgWriteASICHangLogInfo},
            {"__Z32AMDRadeonX5000_kprintfLongStringPKc", wrapAMDRadeonX5000KprintfLongString,
                orgAMDRadeonX5000KprintfLongString},
            {"__ZN35AMDRadeonX5000_AMDAccelEventMachine12eventTimeoutEi", wrapEventTimeout, orgEventTimeout},
            {"__ZN24AMDRadeonX5000_AMDHWGart4initEP30AMDRadeonX5000_IAMDHWInterfaceP16_GART_PARAMETERS", wrapHwGartInit,
                orgHwGartInit},
            {"__ZN25AMDRadeonX5000_AMDGFX9VMM4initEP30AMDRadeonX5000_IAMDHWInterface", wrapVmmInit, orgVmmInit},
        };
        PANIC_COND(!patcher.routeMultiple(index, requests, address, size), "x5000", "Failed to route symbols");

        PANIC_COND(MachInfo::setKernelWriting(true, KernelPatcher::kernelWriteLock) != KERN_SUCCESS, "x5000",
            "Failed to enable kernel writing");
        orgChannelTypes[5] = 1;    // Fix createAccelChannels so that it only starts SDMA0
        // Fix getPagingChannel so that it gets SDMA0
        auto &idx11 = orgChannelTypes[11];
        if (idx11 == 1) {
            idx11 = 0;
        } else {
            orgChannelTypes[12] = 0;
        }

        /*KernelPatcher::LookupPatch patches[] = {
            {&kextRadeonX5000, kdumpASICHangStateOriginal, kdumpASICHangStatePatched,
                arrsize(kdumpASICHangStateOriginal), 1},
        };
        for (auto &patch : patches) {
            patcher.applyLookupPatch(&patch);
            patcher.clearError();
        }*/

        MachInfo::setKernelWriting(false, KernelPatcher::kernelWriteLock);
        PANIC_COND(
            !KernelPatcher::findAndReplace(startHWEngines, PAGE_SIZE, kStartHWEnginesOriginal, kStartHWEnginesPatched),
            "x5000", "Failed to patch startHWEngines");
        DBGLOG("x5000", "Applied SDMA1 patches");

        return true;
    }

    return false;
}

bool X5000::wrapAllocateHWEngines(void *that) {
    callback->amdHw = that;
    callback->orgGFX9PM4EngineConstructor(getMember<void *>(that, 0x3B8) = IOMallocZero(0x1E8));
    callback->orgGFX9SDMAEngineConstructor(getMember<void *>(that, 0x3C0) = IOMallocZero(0x128));
    X6000::callback->orgVCN2EngineConstructor(getMember<void *>(that, 0x3F8) = IOMallocZero(0x198));

    return true;
}

enum HWCapability : uint64_t {
    DisplayPipeCount = 0x04,    // uint32_t
    SECount = 0x34,             // uint32_t
    SHPerSE = 0x3C,             // uint32_t
    CUPerSH = 0x70,             // uint32_t
    HasUVD0 = 0x84,             // bool
    HasUVD1 = 0x85,             // bool
    HasVCE = 0x86,              // bool
    HasVCN0 = 0x87,             // bool
    HasVCN1 = 0x88,             // bool
    HasHDCP = 0x8D,             // bool
    Unknown1 = 0x94,            // bool
    Unknown2 = 0x97,            // bool
    HasSDMAPageQueue = 0x98,    // bool
};

template<typename T>
static inline void setHWCapability(void *that, HWCapability capability, T value) {
    getMember<T>(that, 0x28 + capability) = value;
}

void X5000::wrapSetupAndInitializeHWCapabilities(void *that) {
    auto isRavenDerivative = NRed::callback->chipType < ChipType::Renoir;

    auto *chipName = isRavenDerivative ? NRed::getChipName() : "renoir";
    char filename[128] = {0};
    snprintf(filename, arrsize(filename), "%s_gpu_info.bin", chipName);
    auto &fwDesc = getFWDescByName(filename);
    auto *header = reinterpret_cast<const CommonFirmwareHeader *>(fwDesc.data);
    auto *gpuInfo = reinterpret_cast<const GPUInfoFirmware *>(fwDesc.data + header->ucodeOff);

    setHWCapability<uint32_t>(that, HWCapability::SECount, gpuInfo->gcNumSe);
    setHWCapability<uint32_t>(that, HWCapability::SHPerSE, gpuInfo->gcNumShPerSe);
    setHWCapability<uint32_t>(that, HWCapability::CUPerSH, gpuInfo->gcNumCuPerSh);

    FunctionCast(wrapSetupAndInitializeHWCapabilities, callback->orgSetupAndInitializeHWCapabilities)(that);

    setHWCapability<uint32_t>(that, HWCapability::DisplayPipeCount, isRavenDerivative ? 4 : 6);
    setHWCapability<bool>(that, HWCapability::HasUVD0, false);
    setHWCapability<bool>(that, HWCapability::HasUVD1, false);
    setHWCapability<bool>(that, HWCapability::HasVCE, false);
    setHWCapability<bool>(that, HWCapability::HasVCN0, true);
    setHWCapability<bool>(that, HWCapability::HasVCN1, false);
    setHWCapability<bool>(that, HWCapability::HasHDCP, true);
    setHWCapability<bool>(that, HWCapability::Unknown1, true);     // Set to true in Vega10
    setHWCapability<bool>(that, HWCapability::Unknown2, false);    // Set to false in Vega10
    setHWCapability<bool>(that, HWCapability::HasSDMAPageQueue, false);
}

void *X5000::wrapGetHWChannel(void *that, uint32_t engineType, uint32_t ringId) {
    /** Redirect SDMA1 engine type to SDMA0 */
    return FunctionCast(wrapGetHWChannel, callback->orgGetHWChannel)(that, (engineType == 2) ? 1 : engineType, ringId);
}

void X5000::wrapInitializeFamilyType(void *that) { getMember<uint32_t>(that, 0x308) = AMDGPU_FAMILY_RAVEN; }

void *X5000::wrapAllocateAMDHWDisplay(void *that) {
    return FunctionCast(wrapAllocateAMDHWDisplay, X6000::callback->orgAllocateAMDHWDisplay)(that);
}

void *X5000::wrapNewVideoContext(void *that) {
    return FunctionCast(wrapNewVideoContext, X6000::callback->orgNewVideoContext)(that);
}

void *X5000::wrapCreateSMLInterface(uint32_t configBit) {
    return FunctionCast(wrapCreateSMLInterface, X6000::callback->orgCreateSMLInterface)(configBit);
}

uint64_t X5000::wrapAdjustVRAMAddress(void *that, uint64_t addr) {
    auto ret = FunctionCast(wrapAdjustVRAMAddress, callback->orgAdjustVRAMAddress)(that, addr);
    return ret != addr ? (ret + NRed::callback->fbOffset) : ret;
}

void *X5000::wrapNewShared() { return FunctionCast(wrapNewShared, X6000::callback->orgNewShared)(); }

void *X5000::wrapNewSharedUserClient() {
    return FunctionCast(wrapNewSharedUserClient, X6000::callback->orgNewSharedUserClient)();
}

void *X5000::wrapAllocateAMDHWAlignManager() {
    auto ret = FunctionCast(wrapAllocateAMDHWAlignManager, callback->orgAllocateAMDHWAlignManager)();
    callback->hwAlignMgr = ret;

    callback->hwAlignMgrVtX5000 = getMember<uint8_t *>(ret, 0);
    callback->hwAlignMgrVtX6000 = static_cast<uint8_t *>(IOMallocZero(0x238));

    memcpy(callback->hwAlignMgrVtX6000, callback->hwAlignMgrVtX5000, 0x128);
    *reinterpret_cast<mach_vm_address_t *>(callback->hwAlignMgrVtX6000 + 0x128) =
        X6000::callback->orgGetPreferredSwizzleMode2;
    memcpy(callback->hwAlignMgrVtX6000 + 0x130, callback->hwAlignMgrVtX5000 + 0x128, 0x230 - 0x128);
    return ret;
}

uint32_t X5000::wrapGetDeviceType() { return NRed::callback->chipType < ChipType::Renoir ? 0 : 9; }

void X5000::wrapWriteTail(void *that) {
    static uint32_t callId = 1;
    DBGLOG("x5000", "writeTail call %u << (that: %p)", callId, that);
    callId++;

    auto ring = getMember<uint32_t *>(that, 0x40);
    auto engineType = getMember<uint32_t>(that, 0x7c);
    auto rptr = getMember<uint16_t>(that, 0x50);
    auto wptr = getMember<uint16_t>(that, 0x58);
    DBGLOG("x5000", "Engine type %u, RPTR (cached) = 0x%08X, WPTR = 0x%08X (TS 0x%08X)", engineType, rptr, wptr,
        wptr / 0x80);
    NRed::i386_backtrace();

    if (engineType == 1 || engineType == 2) {
        uint16_t tsOffset = wptr - 0x80;
        for (uint16_t i = 10; i < 0x80; i += 8) {
            if (ring[tsOffset + i] % 0xFF != 4) {
                // No IB left
                break;
            }

            // sdma_v4_0_ring_emit_ib
            uint8_t vmid = (ring[tsOffset + i] >> 16) & 0x10;
            auto ibPtr = (static_cast<uint64_t>(ring[tsOffset + i + 2]) << 32) + ring[tsOffset + i + 1];
            auto ibSize = ring[tsOffset + i + 3];
            DBGLOG("x5000", "writeTail: IB at %p with VMID %u contains %u dword(s)", ibPtr, vmid, ibSize);
            IOSleep(600);

            ibPtr = translateVA(ibPtr, vmid, eAMD_VM_HUB_TYPE::MM);
            DBGLOG("x5000", "writeTail: IB's VA translated to %p", ibPtr);
            IOSleep(600);

            auto *memDesc = IOGeneralMemoryDescriptor::withPhysicalAddress(static_cast<IOPhysicalAddress>(ibPtr),
                4 * ibSize, kIODirectionIn);
            auto *map = memDesc->map();
            ibPtr = map->getVirtualAddress();

            for (uint32_t i = 0; i < ibSize; i++) { DBGLOG("x5000", "ibPtr[%u] = 0x%08X", i, ibPtr[i]); }
            executeSDMAIB(reinterpret_cast<uint32_t *>(ibPtr), ibSize, vmid);

            map->unmap();
            map->release();
            memDesc->release();
        }
    }

    FunctionCast(wrapWriteTail, callback->orgWriteTail)(that);
    callId++;
}

bool X5000::isVRAMAddress(uint64_t addr) { return NRed::callback->vramStart <= addr && addr < NRed::callback->vramEnd; }

uint64_t X5000::vramToFbOffset(uint64_t addr) {
    addr -= NRed::callback->vramStart;
    addr += NRed::callback->fbOffset;
    return addr;
}

uint64_t X5000::translateVA(uint64_t addr, uint8_t vmid, eAMD_VM_HUB_TYPE vmhubType) {
    DBGLOG("x5000", "translateVA << (addr: 0x%llX vmid: %u vmhubType: %u)", addr, vmid, vmhubType);
    uint64_t ret = 0;
    if (vmid == 0) {
        auto rangeStart = getMember<uint64_t>(callback->hwGart, 0x20);
        auto rangeEnd = getMember<uint64_t>(callback->hwGart, 0x28);
        auto *gartPTB = getMember<uint64_t *>(callback->hwGart, 0x58);
        DBGLOG("x5000", "translateVA: rangeStart = 0x%llX, rangeEnd = 0x%llX, gartPTB = %p", rangeStart, rangeEnd,
            gartPTB);
        IOSleep(600);

        if (addr < rangeStart || rangeEnd < addr) return 0;
        ret = gartPTB[(addr - rangeStart) >> 12];
    } else {
        // getContextForVMID
        auto vmContext = getMember<uint8_t *>(callback->vmm, 0x90 + vmid * 0x50 + vmhubType * 0x500);
        auto ctlRoot = reinterpret_cast<void *>(vmContext + 0x90);
        auto rangeStart = getMember<uint64_t>(vmContext, 0xAA0);
        auto rangeEnd = getMember<uint64_t>(vmContext, 0xAA8);
        DBGLOG("x5000", "translateVA: ctlRoot = %p, rangeStart = 0x%llX, rangeEnd = 0x%llX", ctlRoot, rangeStart,
            rangeEnd);
        IOSleep(600);

        if (addr < rangeStart || rangeEnd < addr) return 0;
        uint64_t virtAddrOffset = addr - rangeStart;
        uint64_t sizeToPrint = 0x1000;
        auto entriesBuf = IONew(uint64_t, 1);
        uint32_t entriesFound =
            callback->orgGetVMPT(vmContext, ctlRoot, 0, 0, &virtAddrOffset, &sizeToPrint, entriesBuf, 8);
        if (entriesFound == 0) return 0;
        ret = entriesBuf[0];
    }

    return ret & AMDGPU_GMC_HOLE_MASK;
}

void X5000::executeSDMAPollRegmem(bool memPoll, uint64_t addr, uint32_t ref, uint32_t mask, uint16_t retryCount,
    uint16_t interval, uint8_t vmid) {
    DBGLOG("x5000",
        "executeSDMAPollRegmem << (memPoll: %u addr: 0x%llX ref: 0x%X mask: 0x%X retryCount: 0x%X interval: 0x%X vmid: "
        "%u)",
        memPoll, addr, ref, mask, retryCount, interval, vmid);
    IOSleep(600);

    bool isVA = false;
    IOMemoryDescriptor *memDesc = nullptr;
    IOMemoryMap *map = nullptr;
    if (memPoll) {
        if (isVRAMAddress(addr)) {
            addr = vramToFbOffset(addr);
        } else {
            addr = translateVA(addr, vmid, eAMD_VM_HUB_TYPE::MM);
            DBGLOG("x5000", "executeSDMAPollRegmem: VA translated to %p", addr);
            IOSleep(600);
            memDesc =
                IOGeneralMemoryDescriptor::withPhysicalAddress(static_cast<IOPhysicalAddress>(addr), 4, kIODirectionIn);
            map = memDesc->map();
            addr = map->getVirtualAddress();
            isVA = true;
        }
    }

    for (uint32_t attempt = 0; attempt <= retryCount; attempt++) {
        uint32_t val = 0;
        if (memPoll) {
            val = *(volatile uint32_t *)addr;
        } else {
            val = NRed::callback->readReg32(addr / 4);
        }

        if (val & mask == ref) break;
        IOSleep(interval);
    }

    if (isVA) {
        map->unmap();
        map->release();
        memDesc->release();
    }
}

void X5000::executeSDMAConstFill(uint8_t fillSize, uint32_t srcData, uint64_t dstOffset, uint32_t byteCount,
    uint8_t vmid) {
    DBGLOG("x5000", "executeSDMAConstFill << (fillSize: %u srcData: 0x%X dstOffset: 0x%llX byteCount: 0x%X vmid: 0x%X)",
        fillSize, srcData, dstOffset, byteCount, vmid);
    IOSleep(600);

    bool isVA = true;
    if (isVRAMAddress(dstOffset)) {
        dstOffset = vramToFbOffset(dstOffset);
        isVA = false;
    }

    IOMemoryDescriptor *memDesc = nullptr;
    IOMemoryMap *map = nullptr;

    while (byteCount != 0) {
        uint32_t toWrite = min(byteCount, 0x1000);
        uint64_t dst = dstOffset;
        dstOffset += toWrite;
        byteCount -= toWrite;

        if (isVA) {
            dst = translateVA(dst, vmid, eAMD_VM_HUB_TYPE::MM);
            DBGLOG("x5000", "executeSDMAConstFill: VA %p translated to %p", dstOffset, dst);
            IOSleep(600);
            memDesc = IOGeneralMemoryDescriptor::withPhysicalAddress(static_cast<IOPhysicalAddress>(dst), toWrite,
                kIODirectionOut);
            map = memDesc->map();
            dst = map->getVirtualAddress();
        }

        while (toWrite >= fillSize) {
            switch (fillSize) {
                case 1:
                    *reinterpret_cast<uint8_t *>(dst) = srcData & 0x000000FF;
                    break;
                case 3:
                    *reinterpret_cast<uint8_t *>(dst + 2) = (srcData & 0x00FF0000) >> 0x10;
                    [[fallthrough]];
                case 2:
                    *reinterpret_cast<uint16_t *>(dst) = srcData & 0x0000FFFF;
                    break;
                case 4:
                    *reinterpret_cast<uint32_t *>(dst) = srcData;
                    break;
            }

            toWrite -= fillSize;
            dst += fillSize;
        }

        if (isVA) {
            map->unmap();
            map->release();
            memDesc->release();
        }
    }
}

void X5000::executeSDMAPTEPDEGen(uint64_t pe, uint64_t addr, uint32_t count, uint32_t incr, uint64_t flags) {
    DBGLOG("x5000", "executeSDMAPTEPDEGen << (pe: 0x%llX addr: 0x%llX count: 0x%X incr: 0x%X flags: 0x%llX)", pe, addr,
        count, incr, flags);
    IOSleep(600);

    pe = vramToFbOffset(pe);

    auto *memDesc =
        IOGeneralMemoryDescriptor::withPhysicalAddress(static_cast<IOPhysicalAddress>(pe), 8 * count, kIODirectionOut);
    auto *map = memDesc->map();
    pe = map->getVirtualAddress();

    for (uint32_t i = 0; i < count; i++) {
        uint64_t toWrite = flags | addr;
        DBGLOG("x5000", "executeSDMAPTEPDEGen: Writing 0x%llX to 0x%llx", toWrite, pe);
        *(volatile uint64_t *)pe = toWrite;
        addr += incr;
        pe += 8;
    }

    map->unmap();
    map->release();
    memDesc->release();
}

void X5000::executeSDMAIB(uint32_t *ibPtr, uint32_t ibSize, uint8_t vmid) {
    uint32_t i = 0;
    while (i < ibSize) {
        uint32_t dws = 0;
        uint8_t op = ibPtr[i] & 0x0000FFFF;
        switch (op) {
            case 0x0000:    // SDMA_OP_NOP
                dws = 1;
                break;
            case 0x0008:    // SDMA_OP_POLL_REGMEM
                // sdma_v4_0_wait_reg_mem
                dws = 6;
                bool memPoll = ibPtr[i] >> 31;
                uint8_t func = (ibPtr[i] >> 28) & 7;
                uint32_t addr = (static_cast<uint64_t>(ibPtr[i + 2]) << 32) + ibPtr[i + 1];
                uint32_t ref = ibPtr[i + 3];
                uint32_t mask = ibPtr[i + 4];
                uint16_t retryCount = (ibPtr[i + 5] >> 16) & 0xFFF;
                uint16_t interval = ibPtr[i + 5] & 0xFFFF;

                if (func != 3) {
                    DBGLOG("x5000", "executeSDMAPollRegmem: Unknown func %u", func);
                    return;
                }
                executeSDMAPollRegmem(memPoll, addr, ref, mask, retryCount, interval, vmid);
            case 0x000B:    // SDMA_OP_CONST_FILL
                // sdma_v4_0_emit_fill_buffer
                dws = 5;
                uint8_t fillSize = ibPtr[i] >> 30;
                if (fillSize == 0) fillSize = 4;
                uint64_t dstOffset = (static_cast<uint64_t>(ibPtr[i + 2]) << 32) + ibPtr[i + 1];
                uint32_t srcData = ibPtr[i + 3];
                uint32_t byteCount = ibPtr[i + 4] + 1;
                executeSDMAConstFill(fillSize, srcData, dstOffset, byteCount, vmid);
                break;
            case 0x000C:    // SDMA_SUBOP_PTEPDE_GEN
                // sdma_v4_0_vm_set_pte_pde
                dws = 10;
                uint64_t pe = (static_cast<uint64_t>(ibPtr[i + 2]) << 32) + ibPtr[i + 1];
                uint64_t flags = (static_cast<uint64_t>(ibPtr[i + 4]) << 32) + ibPtr[i + 3];
                uint64_t addr = (static_cast<uint64_t>(ibPtr[i + 6]) << 32) + ibPtr[i + 5];
                uint32_t incr = ibPtr[i + 7];
                uint32_t count = ibPtr[i + 9] + 1;
                executeSDMAPTEPDEGen(pe, addr, count, incr, flags);
                break;
            case 0x000E:    // SDMA_OP_SRBM_WRITE
                // sdma_v4_0_ring_emit_wreg
                dws = 3;
                uint32_t reg = ibPtr[i + 1];
                uint32_t val = ibPtr[i + 2];
                DBGLOG("x5000", "executeSDMASrbmWrite << (reg: 0x%X val: 0x%X)", reg, val);
                IOSleep(600);
                NRed::callback->writeReg32(reg, val);
                break;
            default:
                SYSLOG("x5000", "executeSDMAIB: Unknown op=%u subop=%u", op & 0xFF, op >> 8, ibPtr[i]);
                IOSleep(600);
                return;
        }

        if (op == 0) continue;    // Keep the burst NOPs
        for (uint32_t k = 0; k < dws; k++) {
            ibPtr[i] = 0x00000000;
            i++;
        }
    }
}
void X5000::wrapDispPipeWriteDiagnosisReport(void *that, void *param2, void *param3) {
    DBGLOG("x5000", "dispPipeWriteDiagnosisReport << (that: %p param2: %p param3: %p)", that, param2, param3);
    // FunctionCast(wrapDispPipeWriteDiagnosisReport, callback->orgDispPipeWriteDiagnosisReport)(that, param2, param3);
    // DBGLOG("x5000", "dispPipeWriteDiagnosisReport >> void");
}

uint64_t X5000::wrapWriteASICHangLogInfo(void *that, void *param1) {
    DBGLOG("x5000", "writeASICHangLogInfo << (that: %p param1: %p)", that, param1);
    // auto ret = FunctionCast(wrapWriteASICHangLogInfo, callback->orgWriteASICHangLogInfo)(that, param1);
    // DBGLOG("x5000", "writeASICHangLogInfo >> 0x%llX", ret);
    return 0;
}

void X5000::wrapAMDRadeonX5000KprintfLongString(char *param1) {
    DBGLOG("x5000", "AMDRadeonX5000_kprintfLongString << (param1: %s)", param1);
    NRed::i386_backtrace();
    NRed::sleepLoop("Calling orgAMDRadeonX5000KprintfLongString");
    FunctionCast(wrapAMDRadeonX5000KprintfLongString, callback->orgAMDRadeonX5000KprintfLongString)(param1);
    DBGLOG("x5000", "AMDRadeonX5000_kprintfLongString >> void");
    NRed::sleepLoop("Exiting wrapAMDRadeonX5000KprintfLongString", 3000);
}

void *X5000::wrapEventTimeout(void *that, uint32_t param1) {
    if (param1 == 15) { callback->orgDumpASICHangState(callback->amdHw, false); }
    DBGLOG("x5000", "eventTimeout << (that: %p param1: 0x%X)", that, param1);
    auto ret = FunctionCast(wrapEventTimeout, callback->orgEventTimeout)(that, param1);
    DBGLOG("x5000", "eventTimeout >> %p", ret);
    return ret;
}

bool X5000::wrapHwGartInit(void *that, void *param1, void *param2) {
    callback->hwGart = that;
    auto ret = FunctionCast(wrapHwGartInit, callback->orgHwGartInit)(that, param1, param2);
    return ret;
}

bool X5000::wrapVmmInit(void *that, void *hw) {
    callback->vmm = that;
    auto ret = FunctionCast(wrapVmmInit, callback->orgVmmInit)(that, hw);
    return ret;
}