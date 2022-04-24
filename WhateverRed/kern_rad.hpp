//
//  kern_rad.hpp
//  WhateverRed
//
//  Copyright © 2017 vit9696. All rights reserved.
//  Copyright © 2022 VisualDevelopment. All rights reserved.
//

#ifndef kern_rad_hpp
#define kern_rad_hpp

#include <Headers/kern_patcher.hpp>
#include <Headers/kern_devinfo.hpp>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/graphics/IOFramebuffer.h>
#include "kern_agdc.hpp"
#include "kern_atom.hpp"
#include "kern_con.hpp"

class RAD
{
public:
	void init();
	void deinit();

	void processKernel(KernelPatcher &patcher, DeviceInfo *info);
	bool processKext(KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size);

private:
	static constexpr size_t MaxGetFrameBufferProcs = 3;

	using t_getAtomObjectTableForType = void *(*)(void *that, AtomObjectTableType type, uint8_t *sz);
	using t_populateAccelConfig = void (*)(IOService *accelService, const char **accelConfig);
	using t_getHWInfo = IOReturn (*)(IOService *accelVideoCtx, void *hwInfo);

	static RAD *callbackRAD;
	ThreadLocal<IOService *, 8> currentPropProvider;

	mach_vm_address_t orgTtlIsPicassoDevice{};
	mach_vm_address_t orgSetProperty{}, orgGetProperty{};
	mach_vm_address_t orgGetConnectorsInfoV1{}, orgGetConnectorsInfoV2{};
	t_getAtomObjectTableForType orgGetAtomObjectTableForType = nullptr;
	mach_vm_address_t orgTranslateAtomConnectorInfoV1{}, orgTranslateAtomConnectorInfoV2{};
	mach_vm_address_t orgATIControllerStart{};
	mach_vm_address_t orgNotifyLinkChange{};
	mach_vm_address_t orgPopulateAccelConfig[1]{}, orgGetHWInfo[1]{};
	mach_vm_address_t orgConfigureDevice{}, orgInitLinkToPeer{};
	t_populateAccelConfig wrapPopulateAccelConfig[1] = {populateAccelConfig<0>};

	const char *populateAccelConfigProcNames[1] = {
		"__ZN37AMDRadeonX5000_AMDGraphicsAccelerator19populateAccelConfigEP13IOAccelConfig",
	};

	template <size_t Index>
	static IOReturn populateGetHWInfo(IOService *accelVideoCtx, void *hwInfo)
	{
		if (callbackRAD->orgGetHWInfo[Index])
		{
			int ret = FunctionCast(populateGetHWInfo<Index>, callbackRAD->orgGetHWInfo[Index])(accelVideoCtx, hwInfo);
			callbackRAD->updateGetHWInfo(accelVideoCtx, hwInfo);
			return ret;
		}
		else
			SYSLOG("rad", "populateGetHWInfo invalid use for %lu", Index);
		
		return kIOReturnInvalid;
	}

	t_getHWInfo wrapGetHWInfo[1] = {populateGetHWInfo<0>};

	const char *getHWInfoProcNames[1] = {
		"__ZN35AMDRadeonX5000_AMDAccelVideoContext9getHWInfoEP13sHardwareInfo",
	};

	bool force24BppMode = false;
	bool dviSingleLink = false;
	bool forceOpenGL = false;
	bool fixConfigName = false;
	bool enableGvaSupport = false;
	bool forceVesaMode = false;
	bool forceCodecInfo = false;
	size_t maxHardwareKexts = 1;

	static bool wrapTtlIsPicassoDevice(void* dev);
	void initHardwareKextMods();
	void mergeProperty(OSDictionary *props, const char *name, OSObject *value);
	void mergeProperties(OSDictionary *props, const char *prefix, IOService *provider);
	void applyPropertyFixes(IOService *service, uint32_t connectorNum = 0);
	void updateConnectorsInfo(void *atomutils, t_getAtomObjectTableForType gettable, IOService *ctrl, RADConnectors::Connector *connectors, uint8_t *sz);
	void autocorrectConnectors(uint8_t *baseAddr, AtomDisplayObjectPath *displayPaths, uint8_t displayPathNum, AtomConnectorObject *connectorObjects,
							   uint8_t connectorObjectNum, RADConnectors::Connector *connectors, uint8_t sz);
	void autocorrectConnector(uint8_t connector, uint8_t sense, uint8_t txmit, uint8_t enc, RADConnectors::Connector *connectors, uint8_t sz);
	void reprioritiseConnectors(const uint8_t *senseList, uint8_t senseNum, RADConnectors::Connector *connectors, uint8_t sz);

	template <size_t Index>
	static void populateAccelConfig(IOService *accelService, const char **accelConfig)
	{
		if (callbackRAD->orgPopulateAccelConfig[Index])
		{
			FunctionCast(populateAccelConfig<Index>, callbackRAD->orgPopulateAccelConfig[Index])(accelService, accelConfig);
			callbackRAD->updateAccelConfig(Index, accelService, accelConfig);
		}
		else
		{
			SYSLOG("rad", "populateAccelConfig invalid use for %lu", Index);
		}
	}

	void process24BitOutput(KernelPatcher &patcher, KernelPatcher::KextInfo &info, mach_vm_address_t address, size_t size);
	void processConnectorOverrides(KernelPatcher &patcher, mach_vm_address_t address, size_t size);
	static uint64_t wrapConfigureDevice(void *that, IOPCIDevice *dev);
	static IOService *wrapInitLinkToPeer(void *that, const char *matchCategoryName);
	void processHardwareKext(KernelPatcher &patcher, size_t hwIndex, mach_vm_address_t address, size_t size);
	void setGvaProperties(IOService *accelService);
	void updateAccelConfig(size_t hwIndex, IOService *accelService, const char **accelConfig);

	static bool wrapSetProperty(IORegistryEntry *that, const char *aKey, void *bytes, unsigned length);
	static OSObject *wrapGetProperty(IORegistryEntry *that, const char *aKey);

	static uint32_t wrapGetConnectorsInfoV1(void *that, RADConnectors::Connector *connectors, uint8_t *sz);
	static uint32_t wrapGetConnectorsInfoV2(void *that, RADConnectors::Connector *connectors, uint8_t *sz);

	static uint32_t wrapTranslateAtomConnectorInfoV1(void *that, RADConnectors::AtomConnectorInfo *info, RADConnectors::Connector *connector);
	static uint32_t wrapTranslateAtomConnectorInfoV2(void *that, RADConnectors::AtomConnectorInfo *info, RADConnectors::Connector *connector);
	static bool wrapATIControllerStart(IOService *ctrl, IOService *provider);
	static bool wrapNotifyLinkChange(void *atiDeviceControl, kAGDCRegisterLinkControlEvent_t event, void *eventData, uint32_t eventFlags);
	static IOReturn findProjectByPartNumber(IOService *ctrl, void *properties);
	static bool doNotTestVram(IOService *ctrl, uint32_t reg, bool retryOnFail);
	static void updateGetHWInfo(IOService *accelVideoCtx, void *hwInfo);
};

#endif /* kern_rad_hpp */