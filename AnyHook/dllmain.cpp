// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include "types.h"

void OnAttach(HMODULE);
void CleanUp();
BOOL SetHook(LPCWSTR moduleName, LPCSTR funcName, LPCWSTR callBackModuleName, LPCSTR callBackFuncName, DWORD procId = 0, BOOL fromCreator = TRUE, BOOL global = FALSE, UINT64 callBackAddress = NULL, UINT64 funcAddress = NULL);
void RemoveHook(LPCSTR funcName, DWORD procId = 0, UINT64 funcAddress = NULL);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OnAttach(hModule);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        CleanUp();
        break;
    }
    return TRUE;
}

char* w2a(const wchar_t* wc)
{
    size_t len = wcslen(wc);
    char* c = new char[len + 1]{'\0'};
    if (!c)
        return NULL;
    
    for (size_t i = 0; i < len; i++)
        c[i] = (char)wc[i];
	
	return c;
}

wchar_t* a2w(const char* c)
{
    size_t len = strlen(c);
    wchar_t* wc = new wchar_t[len + 1] {L'\0'};
    if (!wc)
        return NULL;

    for (size_t i = 0; i < len; i++)
        wc[i] = (wchar_t)c[i];

    return wc;
}

BOOL __declspec(dllexport) SetLocalHook(LPCWSTR moduleName, LPCWSTR funcName, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName)
{
    LPSTR cFuncName = w2a(funcName);
    if (!cFuncName)
        return FALSE;
    LPSTR cCallback = w2a(callBackFuncName);
    if (!cCallback)
    {
        delete[] cFuncName;
        return FALSE;
    }

    BOOL ret = SetHook(moduleName, cFuncName, callBackModuleName, cCallback);
    
    delete[] cFuncName;
    delete[] cCallback;

    return ret;
}

BOOL __declspec(dllexport) SetLocalHook(UINT64 funcAddress, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName)
{
    LPSTR cCallback = w2a(callBackFuncName);
    if (!cCallback)
        return FALSE;

    BOOL ret = SetHook(L"", "", callBackModuleName, cCallback, 0, TRUE, FALSE, NULL, funcAddress);

    delete[] cCallback;

    return ret;
}

BOOL __declspec(dllexport) SetLocalHook(LPCWSTR moduleName, LPCWSTR funcName, UINT64 callBackAddress)
{
    LPSTR cFuncName = w2a(funcName);
    if (!cFuncName)
        return FALSE;

    BOOL ret = SetHook(moduleName, cFuncName, L"", "", 0, TRUE, FALSE, callBackAddress);

    delete[] cFuncName;

    return ret;
}

BOOL __declspec(dllexport) SetLocalHook(UINT64 funcAddress, UINT64 callBackAddress)
{
    return SetHook(L"", "", L"", "", 0, TRUE, FALSE, callBackAddress, funcAddress);
}

BOOL __declspec(dllexport) SetGlobalHook(LPCWSTR moduleName, LPCWSTR funcName, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName)
{
    LPCSTR cFuncName = w2a(funcName);
    if (!cFuncName)
        return FALSE;
    LPCSTR cCallback = w2a(callBackFuncName);
    if (!cCallback)
    {
        delete[] cFuncName;
        return FALSE;
    }

    BOOL ret = SetHook(moduleName, cFuncName, callBackModuleName, cCallback, PROCID_GLOBAL_HOOK);

    delete[] cFuncName;
    delete[] cCallback;

    return ret;
}

BOOL __declspec(dllexport) SetGlobalHook(UINT64 funcAddress, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName)
{
    LPCSTR cCallback = w2a(callBackFuncName);
    if (!cCallback)
        return FALSE;

    BOOL ret = SetHook(L"", "", callBackModuleName, cCallback, PROCID_GLOBAL_HOOK, TRUE, TRUE, NULL, funcAddress);

    delete[] cCallback;

    return ret;
}

BOOL __declspec(dllexport) SetGlobalHook(LPCWSTR moduleName, LPCWSTR funcName, UINT64 callBackAddress)
{
    LPCSTR cFuncName = w2a(funcName);
    if (!cFuncName)
        return FALSE;

    BOOL ret = SetHook(moduleName, cFuncName, L"", "", PROCID_GLOBAL_HOOK, TRUE, TRUE, callBackAddress);

    delete[] cFuncName;

    return ret;
}

BOOL __declspec(dllexport) SetGlobalHook(UINT64 funcAddress, UINT64 callBackAddress)
{

    return SetHook(L"", "", L"", "", PROCID_GLOBAL_HOOK, TRUE, TRUE, callBackAddress, funcAddress);
}

BOOL __declspec(dllexport) SetRemoteHook(LPCWSTR moduleName, LPCWSTR funcName, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName, DWORD procId)
{
    LPCSTR cFuncName = w2a(funcName);
    if (!cFuncName)
        return FALSE;
    LPCSTR cCallback = w2a(callBackFuncName);
    if (!cCallback)
    {
        delete[] cFuncName;
        return FALSE;
    }

    BOOL ret = SetHook(moduleName, cFuncName, callBackModuleName, cCallback, procId);

    delete[] cFuncName;
    delete[] cCallback;

    return ret;
}

BOOL __declspec(dllexport) SetRemoteHook(UINT64 funcAddress, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName, DWORD procId)
{
    LPCSTR cCallback = w2a(callBackFuncName);
    if (!cCallback)
        return FALSE;

    BOOL ret = SetHook(L"", "", callBackModuleName, cCallback, procId, TRUE, FALSE, NULL, funcAddress);

    delete[] cCallback;

    return ret;
}

BOOL __declspec(dllexport) SetRemoteHook(LPCWSTR moduleName, LPCWSTR funcName, DWORD procId, UINT64 callBackAddress)
{
    LPCSTR cFuncName = w2a(funcName);
    if (!cFuncName)
        return FALSE;

    BOOL ret = SetHook(moduleName, cFuncName, L"", "", procId, TRUE, FALSE, callBackAddress);

    delete[] cFuncName;

    return ret;
}

BOOL __declspec(dllexport) SetRemoteHook(UINT64 funcAddress, DWORD procId, UINT64 callBackAddress)
{
    return SetHook(L"", "", L"", "", procId, TRUE, FALSE, callBackAddress, funcAddress);
}

void __declspec(dllexport) RemoveLocalHook(LPCWSTR funcName)
{
    LPCSTR cFuncName = w2a(funcName);
    if (!cFuncName)
        return;

    RemoveHook(cFuncName);

    delete[] cFuncName;
}

void __declspec(dllexport) RemoveLocalHook(UINT64 funcAddress)
{
    RemoveHook("", 0, funcAddress);
}

void __declspec(dllexport) RemoveGlobalHook(LPCWSTR funcName)
{
    LPCSTR cFuncName = w2a(funcName);
    if (!cFuncName)
        return;

    RemoveHook(cFuncName, PROCID_GLOBAL_HOOK);

    delete[] cFuncName;
}

void __declspec(dllexport) RemoveGlobalHook(UINT64 funcAddress)
{
    RemoveHook("", PROCID_GLOBAL_HOOK, funcAddress);
}

void __declspec(dllexport) RemoveRemoteHook(LPCWSTR funcName, DWORD procId)
{
    LPCSTR cFuncName = w2a(funcName);
    if (!cFuncName)
        return;

    RemoveHook(cFuncName, procId);

    delete[] cFuncName;
}

void __declspec(dllexport) RemoveRemoteHook(UINT64 funcAddress, DWORD procId)
{
    RemoveHook("", procId, funcAddress);
}

