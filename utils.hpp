#pragma once

#include <Windows.h>
#include "winternl.hpp"

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PLARGE_INTEGER, ULONG, ULONG, HANDLE
);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG
);

typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID
);

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pRtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS *, PCUNICODE_STRING,
    PCUNICODE_STRING, PCUNICODE_STRING, PCUNICODE_STRING,
    PVOID, PCUNICODE_STRING, PCUNICODE_STRING,
    PCUNICODE_STRING, PCUNICODE_STRING, ULONG
);

typedef NTSTATUS(NTAPI* pRtlDestroyProcessParameters)(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
);

#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define myNtCurrentPeb() (myNtCurrentTeb()->ProcessEnvironmentBlock)
#define Add2Ptr(_P_, _X_) reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_P_) + _X_)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

BOOL CopyFileByHandle(HANDLE hSource, HANDLE hTarget);
BOOL GetImageEntryPointRva(HANDLE FileHandle, DWORD *EntryPointRva);
BOOL FillBufferWithPattern(BYTE* buffer, DWORD bufferSize, const BYTE* pattern, DWORD patternSize);
BOOL OverwriteFileContentsWithPattern(HANDLE hFile, const BYTE* pattern, DWORD patternSize);
BOOL WriteRemoteProcessParameters(
    HANDLE hProcess,
    LPCWSTR imageFileName,
    LPCWSTR dllPath,
    LPCWSTR currentDirectory,
    LPCWSTR commandLine,
    void* environmentBlock,
    LPCWSTR windowTitle,
    LPCWSTR desktopInfo,
    LPCWSTR shellInfo,
    LPCWSTR runtimeData
);
