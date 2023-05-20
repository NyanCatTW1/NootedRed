//  Copyright © 2022-2023 ChefKiss Inc. Licensed under the Thou Shalt Not Profit License version 1.0. See LICENSE for
//  details.

#ifndef kern_x5000_hpp
#define kern_x5000_hpp
#include "kern_amd.hpp"
#include <Headers/kern_patcher.hpp>
#include <Headers/kern_util.hpp>

class X5000 {
    friend class X6000;

    public:
    static X5000 *callback;
    void init();
    bool processKext(KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size);

    private:
    t_GenericConstructor orgGFX9PM4EngineConstructor {nullptr};
    t_GenericConstructor orgGFX9SDMAEngineConstructor {nullptr};
    t_dumpASICHangState orgDumpASICHangState {nullptr};
    t_getVMPT orgGetVMPT {nullptr};
    mach_vm_address_t orgSetupAndInitializeHWCapabilities {0};
    mach_vm_address_t orgGetHWChannel {0};
    mach_vm_address_t orgAdjustVRAMAddress {0};
    mach_vm_address_t orgAccelSharedUCStart {0};
    mach_vm_address_t orgAccelSharedUCStop {0};
    mach_vm_address_t orgAllocateAMDHWAlignManager {0};
    mach_vm_address_t orgWriteTail {0};
    mach_vm_address_t orgDispPipeWriteDiagnosisReport {0};
    mach_vm_address_t orgWriteASICHangLogInfo {0};
    mach_vm_address_t orgAMDRadeonX5000KprintfLongString {0};
    mach_vm_address_t orgEventTimeout {0};
    mach_vm_address_t orgHwGartInit {0};
    mach_vm_address_t orgVmmInit {0};
    void *hwAlignMgr {nullptr};
    uint8_t *hwAlignMgrVtX5000 {nullptr};
    uint8_t *hwAlignMgrVtX6000 {nullptr};
    void *amdHw {nullptr};
    void *hwGart {nullptr};
    void *vmm {nullptr};

    static bool wrapAllocateHWEngines(void *that);
    static void wrapSetupAndInitializeHWCapabilities(void *that);
    static void *wrapGetHWChannel(void *that, uint32_t engineType, uint32_t ringId);
    static void wrapInitializeFamilyType(void *that);
    static void *wrapAllocateAMDHWDisplay(void *that);
    static uint64_t wrapAdjustVRAMAddress(void *that, uint64_t addr);
    static void *wrapNewVideoContext(void *that);
    static void *wrapCreateSMLInterface(uint32_t configBit);
    static void *wrapNewShared();
    static void *wrapNewSharedUserClient();
    static void *wrapAllocateAMDHWAlignManager();
    static uint32_t wrapGetDeviceType();
    static void wrapWriteTail(void *that);
    static void wrapDispPipeWriteDiagnosisReport(void *that, void *param2, void *param3);
    static uint64_t wrapWriteASICHangLogInfo(void *that, void *param1);
    static void wrapAMDRadeonX5000KprintfLongString(char *param1);
    static void *wrapEventTimeout(void *that, uint32_t param1);
    static bool wrapHwGartInit(void *that, void *param1, void *param2);
    static bool wrapVmmInit(void *that, void *hw);
    static bool isVRAMAddress(uint64_t addr);
    static uint64_t vramToFbOffset(uint64_t addr);
    static uint64_t translateVA(uint64_t addr, uint8_t vmid, eAMD_VM_HUB_TYPE vmhubType);
    static void executeSDMACopyLinear(uint32_t byteCount, uint64_t srcOffset, uint64_t dstOffset, uint8_t vmid);
    static void executeSDMAPollRegmem(bool memPoll, uint64_t addr, uint32_t ref, uint32_t mask, uint16_t retryCount,
        uint16_t interval, uint8_t vmid);
    static void executeSDMAConstFill(uint8_t fillSize, uint32_t srcData, uint64_t dstOffset, uint32_t byteCount,
        uint8_t vmid);
    static void executeSDMAPTEPDEGen(uint64_t pe, uint64_t addr, uint32_t count, uint32_t incr, uint64_t flags);
    static void executeSDMAIB(uint32_t *ibPtr, uint32_t ibSize, uint8_t vmid);
};

#endif /* kern_x5000_hpp */
