#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <cstdint>

// defs
typedef unsigned __int64 uint64_t;
#define PTE_BASE 0xFFFFF68000000000ULL 
// NOTE: PTE randomised now so add to todo
// patch added with GetPteBase() to dynamically resolve PTE base on runtime

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

// Manual Definitions for Undoc Kernel Exports
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

// Pattern Scanning
BOOLEAN CheckMask(const char* p, const char* pattern, const char* mask) {
    for (; *mask; ++pattern, ++mask, ++p) {
        if (*mask == 'x' && *p != *pattern)
            return FALSE;
    }
    return TRUE;
}

uint64_t FindPattern(uint64_t base, uint32_t size, const char* pattern, const char* mask) {
    for (uint32_t i = 0; i < size; i++) {
        if (CheckMask((const char*)(base + i), pattern, mask)) {
            return base + i;
        }
    }
    return 0;
}

// Get Module Base equiv
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

// Get section base, for .text sec only scanning
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

// Helper: Find .data Section
uint64_t FindDataSection(uint64_t moduleBase, uint32_t* outSize) {
    return GetSectionBase(moduleBase, ".data", outSize);
}

uint64_t GetPteBase() {
    static uint64_t CachedPteBase = 0;
    if (CachedPteBase) return CachedPteBase;

    uint32_t ntosSize = 0;
    uint64_t ntosBase = GetKernelModule("ntoskrnl.exe", &ntosSize);

    uint64_t addr = FindPattern(ntosBase, ntosSize, "\x48\x8B\x05\x00\x00\x00\x00\x48\xC1\xE8\x09\x48\xB8", "xxx????xxxxxx");

    if (addr) {
        int32_t offset = *(int32_t*)(addr + 3);
        CachedPteBase = *(uint64_t*)(addr + 7 + offset);
        return CachedPteBase;
    }
    return 0xFFFFF68000000000ULL;
}

uint64_t GetPteAddress(uint64_t virtualAddress) {
    uint64_t base = GetPteBase();
    return base + ((virtualAddress >> 9) & 0x7FFFFFFFF8);
}