#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <cstdint>

// --- Definitions ---
typedef unsigned __int64 uint64_t;
#define PTE_BASE 0xFFFFF68000000000ULL 
// NOTE: On Win10 2004+, PTE_BASE is randomized. 
// You must calculate it dynamically using MiGetPteAddress or similar in production.

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

// --- Manual Definitions for Undocumented Kernel Exports ---
extern "C" {
    NTKERNELAPI NTSTATUS ObReferenceObjectByName(
        PUNICODE_STRING ObjectName,
        ULONG Attributes,
        PACCESS_STATE AccessState,
        ACCESS_MASK DesiredAccess,
        POBJECT_TYPE ObjectType,
        KPROCESSOR_MODE AccessMode,
        PVOID ParseContext,
        PVOID* Object
    );
    extern POBJECT_TYPE* IoDriverObjectType;
}

extern "C" NTSTATUS ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

extern "C" PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

// --- HELPER: Pattern Scanner ---
// Checks if data at 'p' matches the pattern/mask pair
BOOLEAN CheckMask(const char* p, const char* pattern, const char* mask) {
    for (; *mask; ++pattern, ++mask, ++p) {
        if (*mask == 'x' && *p != *pattern)
            return FALSE;
    }
    return TRUE;
}

// Scans a range of memory for the pattern
uint64_t FindPattern(uint64_t base, uint32_t size, const char* pattern, const char* mask) {
    for (uint32_t i = 0; i < size; i++) {
        if (CheckMask((const char*)(base + i), pattern, mask)) {
            return base + i;
        }
    }
    return 0;
}

// --- Helper: Get Module Base ---
uint64_t GetKernelModule(const char* name, uint32_t* outSize) {
    ULONG bytes = 0;
    ZwQuerySystemInformation(11, NULL, 0, &bytes);
    if (!bytes) return 0;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'mod');
    ZwQuerySystemInformation(11, modules, bytes, &bytes);

    uint64_t base = 0;
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        if (strstr((char*)modules->Modules[i].FullPathName, name)) {
            base = (uint64_t)modules->Modules[i].ImageBase;
            if (outSize) *outSize = modules->Modules[i].ImageSize;
            break;
        }
    }
    ExFreePoolWithTag(modules, 'mod');
    return base;
}

// --- Helper: Get Section Address (for limiting scan to .text) ---
uint64_t GetSectionBase(uint64_t moduleBase, const char* sectionName, uint32_t* outSize) {
    PIMAGE_NT_HEADERS nt = RtlImageNtHeader((PVOID)moduleBase);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, sectionName, strlen(sectionName)) == 0) {
            if (outSize) *outSize = sec[i].Misc.VirtualSize;
            return moduleBase + sec[i].VirtualAddress;
        }
    }
    return 0;
}

// --- Helper: Find .data Section ---
uint64_t FindDataSection(uint64_t moduleBase, uint32_t* outSize) {
    return GetSectionBase(moduleBase, ".data", outSize);
}

// --- Helper: Calculate PTE Address ---
// --- Dynamic OS Detection & PTE Calculation ---
uint64_t GetPteBase() {
    // On Windows 10/11, we can resolve the randomized PTE_BASE 
    // by finding the pattern for the 'MmGetVirtualForPte' function.
    static uint64_t CachedPteBase = 0;
    if (CachedPteBase) return CachedPteBase;

    uint32_t ntosSize = 0;
    uint64_t ntosBase = GetKernelModule("ntoskrnl.exe", &ntosSize);

    // Pattern for 'mov rax, [dynamic_pte_base]' in MmPteToAddress
    // This varies, but a common way is to resolve MmGetVirtualForPte 
    uint64_t addr = FindPattern(ntosBase, ntosSize, "\x48\x8B\x05\x00\x00\x00\x00\x48\xC1\xE8\x09\x48\xB8", "xxx????xxxxxx");

    if (addr) {
        int32_t offset = *(int32_t*)(addr + 3);
        CachedPteBase = *(uint64_t*)(addr + 7 + offset);
        return CachedPteBase;
    }

    // Fallback for older systems (pre-randomization)
    return 0xFFFFF68000000000ULL;
}

uint64_t GetPteAddress(uint64_t virtualAddress) {
    uint64_t base = GetPteBase();
    return base + ((virtualAddress >> 9) & 0x7FFFFFFFF8);
}