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
    mach_vm_address_t orgSetupAndInitializeHWCapabilities {0};
    mach_vm_address_t orgGetHWChannel {0};
    mach_vm_address_t orgAdjustVRAMAddress {0};
    mach_vm_address_t orgAccelSharedUCStart {0};
    mach_vm_address_t orgAccelSharedUCStop {0};
    mach_vm_address_t orgAllocateAMDHWAlignManager {0};
    mach_vm_address_t orgUpdateContiguousPTEsWithDMAUsingAddr {0};
    mach_vm_address_t orgWriteTail {0};
    void *hwAlignMgr {nullptr};
    uint8_t *hwAlignMgrVtX5000 {nullptr};
    uint8_t *hwAlignMgrVtX6000 {nullptr};

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
    static void wrapUpdateContiguousPTEsWithDMAUsingAddr(void *that, uint64_t pe, uint64_t count, uint64_t addr,
        uint64_t flags, uint64_t incr);
    static void wrapWriteTail(void *that);
};

#endif /* kern_x5000_hpp */
