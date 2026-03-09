# KernelRootkit

## Overview

KernelRootkit is an educational POC Windows kernelmode rootkit. It employs ROP to bypass the NX (No execute) bit on a target kernel driver's data section, enabling the execution of arbitrary shellcode in kernel space. This project is intended solely for research and educational purposes to illustrate kernel exploitation concepts and further my understanding of system internals and developing APT's. 

**WARNING:** This code is highly experimental and dangerous. If you want to test it within a VM, please make sure nothing important is stored on it. 

## How It Works

The rootkit operates through the following high-level steps:

1. **Gadget Discovery**: Scans the `.text` section of `ntoskrnl.exe` for ROP gadgets using pattern matching.
2. **Target Selection**: Identifies a suitable target driver (e.g., `disk.sys`) with a writable `.data` section.
3. **Memory Mapping**: Uses an MDL (Memory Descriptor List) to map the target's `.data` section as writable.
4. **ROP Chain Construction**: Builds a ROP chain that:
   - Locates the Page Table Entry (PTE) for the target memory.
   - Clears the NX bit to allow code execution.
   - Jumps to the shellcode payload.
5. **Payload Injection**: Injects the ROP chain, context structure, and shellcode into the target's memory.
6. **Hook Installation**: Replaces the target's `IRP_MJ_DEVICE_CONTROL` dispatch routine with the ROP chain address.
7. **Execution**: When the hooked dispatch is called, the ROP chain executes, flips the NX bit, and runs the covert payload.

The payload demonstrates successful execution by creating a proof file (`C:\StompProof.txt`) and then forwarding the IRP to the original dispatch routine.

## Security Mechanisms Bypassed

This rootkit demonstrates bypasses for several Windows kernel security mechanisms:

- **Data Execution Prevention (DEP) / NX Bit**: The core bypass involves using ROP to locate and modify the Page Table Entry (PTE) of the target memory region, clearing the NX (No eXecute) bit. This allows code execution from a data-only section, violating DEP protections.

- **Address Space Layout Randomization (ASLR) / Kernel ASLR (KASLR)**: The rootkit dynamically resolves the base addresses of kernel modules (e.g., `ntoskrnl.exe`) using system information queries. PTE addresses are calculated as it loads so ASLR gets bypassed.

- **Code Integrity and Memory Protections**: ALlows a payload to be installed covertly and with very little hope of being discovered.By injecting and executing shellcode in another driver's writable `.data` section, it circumvents restrictions on executing code from non-executable memory regions.

- **Covert communication** Usermode programs are able to communicate with the kernel driver via a hooked windows API. Traditionally, using pipes, IOCTL's or other communication methods user-kernel communication can get "sniffed" by other kernel mode drivers, eg. endpoint detection, other rootkits running, anti-cheats. The more modern approach uses shared memory, where both processes use polling to read and write from this memory block to communicate (even symmetric encryption can be used here to add prevent data sniffing). EDR solutions are picking up on this as they can enumerate encrypted shared memory and check entropy. This rootkit hooks a windows API, so when the usermode program calls it, it sends a "communication packet", basically a struct with everything we want to send" and the driver will intercept this and can return with its answer. Hooking these functions works thanks to driver stomping, when the API is scanned by an antivirus, it checks if the inline hook jumps outside the memory range of the driver. Since it doesnt, as all the code lives in data section and ROP is used to switch the NX bit, it passes this check. In future, ill consider switching to a different hook (IAT/EAT) for good measure. 


## Architecture

- **Driver Entry**: `DriverEntry` in `main.cpp` initializes the rootkit.
- **Utilities**: `Utils.h` provides pattern scanning, module resolution, and section parsing.
- **Payload**: `Payload.h` defines the ROP chain structure, context, and shellcode.

## Building

No build or setup instructions will be published for this project, if you want to run this for research and need help setting it up, i recommend using kdmapper and a VM with WinDBG attached. 

## Legal and Ethical Notice

This project was developed to further my understanding on developing kernel drivers in Windows and security techniques used and their weaknesses. Misusing this project is a crime, only run this within a VM that you own.

## License

This project is released under the MIT License. See LICENSE for details.

