// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include <string>
#include <winternl.h>

using namespace std;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

__declspec(dllexport) BOOL WINAPI ShadowTerminateProcess(HANDLE hTarget, UINT exitCode)
{
    MessageBox(NULL, L"It's CALLBACK!!!", NULL, 0);
    MessageBox(NULL, to_wstring((UINT64)hTarget).data(), NULL, 0);
    MessageBox(NULL, to_wstring((UINT64)GetProcessId(hTarget)).data(), NULL, 0);
    return TRUE;
}

__declspec(dllexport) void WINAPI ShadowExitProcess(UINT exitCode)
{
    MessageBox(NULL, to_wstring(GetCurrentProcessId()).data(), NULL, 0);
    //MessageBox(NULL, to_wstring(exitCode).data(), NULL, 0);
    ExitProcess(exitCode);
}

__declspec(dllexport) __kernel_entry NTSTATUS NtQuerySystemInformationShadow(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, // What info to be retrieved. 
    PVOID                    SystemInformation,     // A buffer that receives the requested information.
    ULONG                    SystemInformationLength, // The size of the buffer pointed to by the SystemInformation parameter, in bytes.
    PULONG                   ReturnLength // Optional.
)
{
    // Calling og function (Trampoline)
    //NTSTATUS status = qsi(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (SystemProcessInformation == SystemInformationClass)
    {
        SYSTEM_PROCESS_INFORMATION* pCurrent;
        SYSTEM_PROCESS_INFORMATION* pNext = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;

        do
        {
            pCurrent = pNext;
            pNext = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

            if (wcsncmp(pNext->ImageName.Buffer, L"Test.exe", pNext->ImageName.Length) == 0)
            {
                if (pNext->NextEntryOffset == 0)
                    pCurrent->NextEntryOffset = 0;
                else
                    pCurrent->NextEntryOffset += pNext->NextEntryOffset;
            }

        } while (pCurrent->NextEntryOffset != 0);

    }

    return 0;
}


