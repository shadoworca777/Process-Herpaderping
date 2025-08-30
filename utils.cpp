#include "utils.hpp"

BOOL CopyFileByHandle(HANDLE hSource, HANDLE hTarget) {
    DWORD totalSize = GetFileSize(hSource, nullptr);
    if (totalSize == 0) return TRUE; // 空ファイルなら何もしない

    if (SetFilePointer(hSource, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) return FALSE;
    if (SetFilePointer(hTarget, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) return FALSE;

    BYTE* buffer = new BYTE[totalSize];
    if (!buffer) return FALSE;

    DWORD bytesRead = 0;
    if (!ReadFile(hSource, buffer, totalSize, &bytesRead, nullptr) ||
        bytesRead != totalSize) {
        delete[] buffer;
        return FALSE;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hTarget, buffer, bytesRead, &bytesWritten, nullptr) ||
        bytesWritten != bytesRead) {
        delete[] buffer;
        return FALSE;
    }

    delete[] buffer;

    return SetEndOfFile(hTarget);
}

BOOL GetImageEntryPointRva(HANDLE FileHandle, DWORD *EntryPointRva) {
    if (!EntryPointRva) return FALSE;
    *EntryPointRva = 0;

    LARGE_INTEGER fileSize = {0};
    if (!GetFileSizeEx(FileHandle, &fileSize)) return FALSE;

    HANDLE mapping = CreateFileMappingW(
        FileHandle,
        nullptr,
        PAGE_READONLY,
        fileSize.HighPart,
        fileSize.LowPart,
        nullptr
    );
    if (!mapping) return FALSE;

    void* view = MapViewOfFile(
        mapping,
        FILE_MAP_READ,
        0,
        0,
        static_cast<SIZE_T>(fileSize.QuadPart)
    );
    CloseHandle(mapping);

    if (!view) return FALSE;

    auto dosHeader = (PIMAGE_DOS_HEADER)view;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(view);
        return FALSE;
    }

    auto ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)view + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        UnmapViewOfFile(view);
        return FALSE;
    }

    if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        *EntryPointRva = ntHeader->OptionalHeader.AddressOfEntryPoint;
    }
    else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto ntHeader64 = (PIMAGE_NT_HEADERS64)ntHeader;
        *EntryPointRva = ntHeader64->OptionalHeader.AddressOfEntryPoint;
    }
    else {
        UnmapViewOfFile(view);
        return FALSE;
    }

    UnmapViewOfFile(view);
    return TRUE;
}

BOOL FillBufferWithPattern(BYTE* buffer, DWORD bufferSize, const BYTE* pattern, DWORD patternSize) {
    if (!buffer || !pattern || bufferSize == 0 || patternSize == 0) return FALSE;

    DWORD offset = 0;
    while (offset < bufferSize) {
        DWORD len = (bufferSize - offset < patternSize) ? (bufferSize - offset) : patternSize;
        memcpy(buffer + offset, pattern, len);
        offset += len;
    }

    return TRUE;
}

BOOL OverwriteFileContentsWithPattern(HANDLE hFile, const BYTE* pattern, DWORD patternSize) {
    if (!hFile || !pattern || patternSize == 0) return FALSE;

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) return FALSE;

    if (SetFilePointer(hFile, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) return FALSE;

    BYTE* buffer = new BYTE[fileSize];
    if (!buffer) return FALSE;

    if (!FillBufferWithPattern(buffer, fileSize, pattern, patternSize)) {
        delete[] buffer;
        return FALSE;
    }

    DWORD bytesWritten = 0;
    BOOL writeSuccess = WriteFile(hFile, buffer, fileSize, &bytesWritten, nullptr);

    delete[] buffer;

    if (!writeSuccess || bytesWritten != fileSize) return FALSE;
    if (!FlushFileBuffers(hFile)) return FALSE;

    return TRUE;
}

static void MyInitUnicodeString(PUNICODE_STRING ustr, PCWSTR src) {
    if (src) {
        size_t len = wcslen(src) * sizeof(WCHAR);
        ustr->Buffer = (PWSTR)src;
        ustr->Length = (USHORT)len;
        ustr->MaximumLength = (USHORT)(len + sizeof(WCHAR));
    }
    else {
        ustr->Buffer = nullptr;
        ustr->Length = 0;
        ustr->MaximumLength = 0;
    }
}

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
    LPCWSTR runtimeData)
{
    PROCESS_BASIC_INFORMATION pbi = {};
    HMODULE ntdll = GetModuleHandleA("ntdll");
    pNtQueryInformationProcess myNtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    NTSTATUS status = myNtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        nullptr
    );
    if (!NT_SUCCESS(status)) return FALSE;

    UNICODE_STRING image;
    MyInitUnicodeString(&image, imageFileName);

    UNICODE_STRING dllPathU = {};
    UNICODE_STRING currentDirU = {};
    UNICODE_STRING commandLineU = {};
    UNICODE_STRING windowTitleU = {};
    UNICODE_STRING desktopInfoU = {};
    UNICODE_STRING shellInfoU = {};
    UNICODE_STRING runtimeDataU = {};

    if (dllPath)          MyInitUnicodeString(&dllPathU, dllPath);
    if (currentDirectory) MyInitUnicodeString(&currentDirU, currentDirectory);
    if (commandLine)      MyInitUnicodeString(&commandLineU, commandLine);
    if (windowTitle)      MyInitUnicodeString(&windowTitleU, windowTitle);
    if (desktopInfo)      MyInitUnicodeString(&desktopInfoU, desktopInfo);
    if (shellInfo)        MyInitUnicodeString(&shellInfoU, shellInfo);
    if (runtimeData)      MyInitUnicodeString(&runtimeDataU, runtimeData);

    RTL_USER_PROCESS_PARAMETERS* params = nullptr;

    pRtlCreateProcessParametersEx myRtlCreateProcessParametersEx = (pRtlCreateProcessParametersEx)GetProcAddress(ntdll, "RtlCreateProcessParametersEx");
    status = myRtlCreateProcessParametersEx(
        &params,
        &image,
        dllPath ? &dllPathU : nullptr,
        currentDirectory ? &currentDirU : nullptr,
        commandLine ? &commandLineU : nullptr,
        environmentBlock,
        windowTitle ? &windowTitleU : nullptr,
        desktopInfo ? &desktopInfoU : nullptr,
        shellInfo ? &shellInfoU : nullptr,
        runtimeData ? &runtimeDataU : nullptr,
        0
    );

    if (!NT_SUCCESS(status)) return FALSE;

    SIZE_T totalSize = params->MaximumLength + params->EnvironmentSize;

    pRtlDestroyProcessParameters myRtlDestroyProcessParameters = (pRtlDestroyProcessParameters)GetProcAddress(ntdll, "RtlDestroyProcessParameters");

    void* remoteMemory = VirtualAllocEx(
        hProcess,
        nullptr,
        totalSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!remoteMemory) {
        myRtlDestroyProcessParameters(params);
        return FALSE;
    }

    if (params->Environment) {
        params->Environment = (PVOID)((PBYTE)remoteMemory + params->Length);
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, params, totalSize, nullptr)) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        myRtlDestroyProcessParameters(params);
        return FALSE;
    }

    PVOID pebProcessParams = (PBYTE)pbi.PebBaseAddress + FIELD_OFFSET(PEB, ProcessParameters);

    if (!WriteProcessMemory(hProcess, pebProcessParams, &remoteMemory, sizeof(remoteMemory), nullptr)) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        myRtlDestroyProcessParameters(params);
        return FALSE;
    }

    myRtlDestroyProcessParameters(params);
    return TRUE;
}
