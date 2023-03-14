# NootedRed ![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/NootInc/NootedRed/main.yml?branch=master&logo=github&style=for-the-badge)

Through hard work come great results.

An AMD iGPU support [Lilu](https://github.com/acidanthera/Lilu) plugin.

The Source Code of this Original Work is licensed under the `Thou Shalt Not Profit License version 1.0`. See [`LICENSE`](https://github.com/NootInc/NootedRed/blob/master/LICENSE)

Thanks [Acidanthera](https://github.com/Acidanthera) for the Navi FB backlight code in [WhateverGreen](https://github.com/Acidanthera/WhateverGreen).

## Recommendations

- Add [SSDT-PNLF.aml](Assets/SSDT-PNLF.aml) by [@ChefKissInc](https://github.com/ChefKissInc) and [@ExtremeXT](https://github.com/ExtremeXT)
- Use `MacBookPro16,3`, `MacBookPro16,4` or `MacPro7,1` SMBIOS
- Add [AGPMInjector.kext](Assets/AGPMInjector.kext.zip) by [Visual](https://github.com/ChefKissInc). Supports only `MacBookPro16,3`, `MacBookPro16,4` or `MacPro7,1` SMBIOS.

## FAQ

### Can I have an AMD dGPU installed on the system?

We are mixing AMDRadeonX5000 for GCN 5, AMDRadeonX6000 for VCN, and AMDRadeonX6000Framebuffer for DCN, so your system must not have a GCN 5 or RDNA AMD dGPU, as this kext will conflict with them.

### How functional is the kext?

This project is under active research and development; There will be crashes here and there, and it is incompatible with Renoir-based iGPUs (Like Cezanne, Lucienne, etc).

The kext is fully functional more or less on Raven/Raven2-based iGPUs (Like Picasso).

See repository issues for more information.

### On which macOS versions am I able to use this on?

Due to the complexity and secrecy of the Metal 2/3 drivers, adding support for non-existent logic is basically impossible.

The required logic for our iGPUs has been purged from the AMD kexts since Monterey.

This cannot be resolved without breaking macOS' integrity and potentially even stability.

Injecting the GPU kexts is not possible during the OpenCore injection stage. The prelink stage fails for kexts of this type as their dependencies aren't contained in the Boot Kext Collection, where OpenCore injects kexts to, they're in the System Kext Collection.

In conclusion, this kext is constricted to Big Sur since there are too many incompatibilities with older and newer macOS versions.

### I get a panic saying "Failed to get VBIOS from VRAM", how can I fix it?

Ensure Legacy Boot/CSM is disabled in your BIOS settings.

## Project members

- [@ChefKissInc](https://github.com/ChefKissInc) | Project lead, Linux shitcode analyser and kernel extension developer. Extensive knowledge of OS inner workings
- [@NyanCatTW1](https://github.com/NyanCatTW1) | Reverse Engineering and Python automation magician. His Ghidra RedMetaClassAnalyzer script has made the entire process way painless by automagically discovering C++ v-tables for classes.
