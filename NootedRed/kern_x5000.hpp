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
    t_dumpASICHangState orgdumpASICHangState {nullptr};
    mach_vm_address_t orgSetupAndInitializeHWCapabilities {0};
    mach_vm_address_t orgGetHWChannel {0};
    mach_vm_address_t orgAdjustVRAMAddress {0};
    mach_vm_address_t orgAccelSharedUCStart {0};
    mach_vm_address_t orgAccelSharedUCStop {0};
    mach_vm_address_t orgAllocateAMDHWAlignManager {0};
    mach_vm_address_t orgWriteTail {0};
    mach_vm_address_t orgSubmitBuffer {0};
    mach_vm_address_t orgDispPipeWriteDiagnosisReport {0};
    mach_vm_address_t orgWriteASICHangLogInfo {0};
    mach_vm_address_t orgAMDRadeonX5000KprintfLongString {0};
    mach_vm_address_t orgEventTimeout {0};
    void *hwAlignMgr {nullptr};
    uint8_t *hwAlignMgrVtX5000 {nullptr};
    uint8_t *hwAlignMgrVtX6000 {nullptr};
    void *amdHW {nullptr};

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
    static void wrapSubmitBuffer(void *that, void *cmdDesc);
    static void wrapDispPipeWriteDiagnosisReport(void *that, void *param2, void *param3);
    static uint64_t wrapWriteASICHangLogInfo(void *that, void *param1);
    static void wrapAMDRadeonX5000KprintfLongString(char *param1);
    static void *wrapEventTimeout(void *that, uint32_t param1);
};

#endif /* kern_x5000_hpp */
