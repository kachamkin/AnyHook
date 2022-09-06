// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include <string>

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



