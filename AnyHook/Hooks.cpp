#include "pch.h"
#include "types.h"
#include "data.h"

using namespace std;

void AddLogMessage(LPCWSTR message, LPCSTR file, int line, BOOL bError = TRUE)
{
    HANDLE log = RegisterEventSource(NULL, L"AnyHook");
    if (log)
    {
        LPCWSTR wFile = a2w(file);
        wstring wsMessage = wstring(wFile) + L", line " + to_wstring(line) + L", process " + to_wstring(GetCurrentProcessId()) +  L": " + message;
        LPCWSTR data = wsMessage.data();

        ReportEvent(log, bError ? EVENTLOG_ERROR_TYPE : EVENTLOG_INFORMATION_TYPE, 0, 1, NULL, 1, 0, &data, NULL);
        DeregisterEventSource(log);

        delete[] wFile;
    };
}

LRESULT CALLBACK WINAPI MsgHookingProc(int iCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(hHook, iCode, wParam, lParam);
}

void OnAttach(HMODULE hModule)
{
    hDll = hModule;
    if (creatorId && GetCurrentProcessId() != creatorId)
    {
        if (!checkHookThreadCreated)
        {
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaitForHooks, NULL, 0, NULL);
            if (hThread)
            {
                CloseHandle(hThread);
                checkHookThreadCreated = TRUE;
            }
        }
        if (!removeThreadCreated)
        {
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaitForRemove, NULL, 0, NULL);
            if (hThread)
            {
                CloseHandle(hThread);
                removeThreadCreated = TRUE;
            }
        }
    }
}

void DeleteTBH(PTBHOOKED tbh)
{
    delete[] tbh->callBack;
    delete[] tbh->callBackModuleName;
    delete[] tbh->funcName;
    delete[] tbh->moduleName;
    delete tbh;
}

void CleanUp()
{
    DWORD procId = GetCurrentProcessId();

    if (creatorId && procId == creatorId)
    {
        if (hHook)
            UnhookWindowsHookEx(hHook);
    }
    else
    {
        HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
        if (hMut)
        {
            if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
            {
                ReadMapping(L"Global\\hooks");
                ReadMapping(L"Global\\globalHooks");
                ReadMapping(L"Global\\toBeHooked");
                ReadMapping(L"Global\\toBeRemoved");

                for (long long i = toBeHooked.size() - 1; i >= 0; i--)
                {
                    if (procId == toBeHooked[i]->procId)
                    {
                        DeleteTBH(toBeHooked[i]);
                        toBeHooked.erase(toBeHooked.begin() + i);
                    }
                }

                for (long long i = toBeRemoved.size() - 1; i >= 0; i--)
                {
                    if (procId == toBeRemoved[i]->procId)
                    {
                        DeleteTBH(toBeRemoved[i]);
                        toBeRemoved.erase(toBeRemoved.begin() + i);
                    }
                }

                vector<string> found;
                string strProcId = to_string(procId);

                for (pair<string, HOOKREC> p : hooks)
                    if (strProcId == p.first.substr(0, p.first.find(":")))
                        found.push_back(p.first);
                for (size_t i = 0; i < found.size(); i++)
                    RemoveHook(found[i].substr(found[i].find(":") + 1).data(), procId, NULL);

                found.clear();
                for (pair<string, HOOKREC> p : globalHooks)
                    if (strProcId == p.first.substr(0, p.first.find(":")))
                        found.push_back(p.first);
                for (size_t i = 0; i < found.size(); i++)
                    globalHooks.erase(found[i]);

                WriteMapping(L"Global\\hooks");
                WriteMapping(L"Global\\globalHooks");
                WriteMapping(L"Global\\toBeHooked");
                WriteMapping(L"Global\\toBeRemoved");

                ReleaseMutex(hMut);
            }
            CloseHandle(hMut);
        }
    }
}

BOOL CreateHook(unsigned __int64 ui64AddressFunc, unsigned __int64 ui64AddressShadowFunc, PHOOKREC phr)
{
    DWORD dwOldAttr;

    phr->ui64AddressFunc = ui64AddressFunc;
    phr->ui64AddressShadowFunc = ui64AddressShadowFunc;
    phr->phNew.address = ui64AddressShadowFunc;
    memcpy((void*)&phr->phOld, (LPVOID)phr->ui64AddressFunc, sizeof(PROCHOOK));

    if (!VirtualProtect((void*)phr->ui64AddressFunc, sizeof(PROCHOOK), PAGE_EXECUTE_READWRITE, &dwOldAttr))
    {
        AddLogMessage(L"Couldn't unprotect memory", __FILE__, __LINE__);
        return FALSE;
    }

    HookFunction(phr);
    return TRUE;
}

void DestroyHook(PHOOKREC phr)
{
    UnhookFunction(phr);

    phr->ui64AddressFunc = 0;
    phr->ui64AddressShadowFunc = 0;
    phr->phNew.address = 0;

    memset((void*)&phr->phOld, 0, sizeof(PROCHOOK));
}

void HookFunction(PHOOKREC phr)
{
    memcpy((void*)phr->ui64AddressFunc, (const void*)&phr->phNew, sizeof(PROCHOOK));
}

void UnhookFunction(PHOOKREC phr)
{
    memcpy((void*)phr->ui64AddressFunc, (const void*)&phr->phOld, sizeof(PROCHOOK));
}

BOOL AreThereGlobalHooks(LPCSTR funcName, DWORD procId = 0)
{
	BOOL ret = FALSE;

	HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
	if (hMut)
	{
		if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
		{
			ReadMapping(L"Global\\globalHooks");
			if (procId)
			{
				if (globalHooks.size() && globalHooks.find(to_string(procId) + ":" + funcName) != globalHooks.end())
					ret = TRUE;
			}
			else
				for (pair<string, HOOKREC> p : globalHooks)
					if (funcName == p.first.substr(p.first.find(":") + 1))
					{
						ret = TRUE;
						break;
					}
			ReleaseMutex(hMut);
		}
		CloseHandle(hMut);
	}

	return ret;
}

BOOL AreThereHooks(LPCSTR funcName, DWORD procId)
{
    BOOL ret = FALSE;
    
    HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
    if (hMut)
    {
        if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
        {
            ReadMapping(L"Global\\hooks");
            for (pair<string, HOOKREC> p : hooks)
                if (funcName == p.first.substr(p.first.find(":") + 1))
                {
                    ret = TRUE;
                    break;
                }
            ReleaseMutex(hMut);
        }
        CloseHandle(hMut);
    }

    return ret;
}

HMODULE IsModuleInUse(UINT64 address)
{
    HMODULE hMod = NULL;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)address, &hMod))
        return NULL;

    HMODULE ret = hMod;

    HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
    if (hMut)
    {
        if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
        {
            ReadMapping(L"Global\\hooks");
            ReadMapping(L"Global\\globalHooks");

            for (pair<string, HOOKREC> p : globalHooks)
            {
                HMODULE hCurrMod = NULL;
                if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)p.second.ui64AddressShadowFunc, &hCurrMod))
                {
                    ret = NULL;
                    break;
                }
                if (hMod == hCurrMod)
                {
                    ret = NULL;
                    break;
                }
            }

            if (!ret)
            {
                for (pair<string, HOOKREC> p : hooks)
                {
                    HMODULE hCurrMod = NULL;
                    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)p.second.ui64AddressShadowFunc, &hCurrMod))
                    {
                        ret = NULL;
                        break;
                    }
                    if (hMod == hCurrMod)
                    {
                        ret = NULL;
                        break;
                    }
                }
            }

            ReleaseMutex(hMut);
        }
        CloseHandle(hMut);
    }

    return ret;
}

void WaitForRemove()
{
    HANDLE hClean = OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"Global\\CleanUp");
    HANDLE hRem = OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"Global\\SignalRemove");
    HANDLE handles[2]{ hClean, hRem };
    if (hRem && hClean)
    {
        DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0)
        {
            CloseHandle(hRem);
            CloseHandle(hClean);
            FreeLibraryAndExitThread(hDll, 0);
        }
        else if (waitResult == WAIT_OBJECT_0 + 1)
        {
            HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
            if (hMut)
            {
                if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
                {
                    DWORD currProcId = GetCurrentProcessId();
                    ReadMapping(L"Global\\toBeRemoved");
                    size_t oldSize = toBeRemoved.size();
                    for (long long i = oldSize - 1; i >= 0; i--)
                    {
                        if (toBeRemoved[i]->procId == currProcId && AreThereHooks((toBeRemoved[i]->funcAddress ? to_string(toBeRemoved[i]->funcAddress).data() : toBeRemoved[i]->funcName), toBeRemoved[i]->procId) || toBeRemoved[i]->procId == PROCID_GLOBAL_HOOK)
                        {
                            RemoveHook(toBeRemoved[i]->funcName, currProcId, toBeRemoved[i]->funcAddress);
                            if (toBeRemoved[i]->procId == currProcId || !AreThereGlobalHooks(toBeRemoved[i]->funcName))
                            {
                                DeleteTBH(toBeRemoved[i]);
                                toBeRemoved.erase(toBeRemoved.begin() + i);
                            }
                        }
                    }
                    WriteMapping(L"Global\\toBeRemoved");
                    ReleaseMutex(hMut);
                    if (oldSize && !toBeRemoved.size())
                        ResetEvent(hRem);
                }
                CloseHandle(hMut);
            }
            CloseHandle(hRem);
            WaitForRemove();
        }
    }
}

void WaitForHooks()
{
    HANDLE hClean = OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"Global\\CleanUp");
    HANDLE hCheck = OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE , FALSE, L"Global\\SignalCheckHooks");
    HANDLE handles[2]{ hClean, hCheck };
    if (hCheck && hClean)
    {
        DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0)
        {
            CloseHandle(hCheck);
            CloseHandle(hClean);
            FreeLibraryAndExitThread(hDll, 0);
        }
        else if (waitResult == WAIT_OBJECT_0 + 1)
        {
            HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
            if (hMut)
            {
                if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
                {
                    DWORD currProcId = GetCurrentProcessId();
                    ReadMapping(L"Global\\toBeHooked");
                    size_t oldSize = toBeHooked.size();
                    for (long long i = oldSize - 1; i >= 0; i--)
                    {
                        if (toBeHooked[i]->procId == currProcId || toBeHooked[i]->procId == PROCID_GLOBAL_HOOK)
                        {
                            if (!SetHook(toBeHooked[i]->moduleName, toBeHooked[i]->funcName, toBeHooked[i]->callBackModuleName, toBeHooked[i]->callBack, currProcId, FALSE, toBeHooked[i]->procId == PROCID_GLOBAL_HOOK, toBeHooked[i]->callBackAddress, toBeHooked[i]->funcAddress) || toBeHooked[i]->procId == currProcId)
                            {
                                DeleteTBH(toBeHooked[i]);
                                toBeHooked.erase(toBeHooked.begin() + i);
                            }
                        }
                    }
                    WriteMapping(L"Global\\toBeHooked");
                    ReleaseMutex(hMut);
                    if (oldSize && !toBeHooked.size())
                        ResetEvent(hCheck);
                }
                CloseHandle(hMut);
            }
            CloseHandle(hCheck);
            CloseHandle(hClean);
            WaitForHooks();
        }
    }
}

BOOL Initialize(BOOL fromCreator = TRUE)
{
    if (!creatorId && fromCreator)
    {
        creatorId = GetCurrentProcessId();
        hRemove = CreateEvent(NULL, TRUE, FALSE, L"Global\\SignalRemove");
        hCheckHooks = CreateEvent(NULL, TRUE, FALSE, L"Global\\SignalCheckHooks");
        hCleanUp = CreateEvent(NULL, TRUE, FALSE, L"Global\\CleanUp");
        hMutex = CreateMutex(NULL, TRUE, L"Global\\ReadWriteEnabled");
        if (hMutex)
            ReleaseMutex(hMutex);

        if (!hRemove || !hCheckHooks || !hMutex)
        {
            AddLogMessage(L"Initialization error: one or more sync handles are zero", __FILE__, __LINE__);
            return FALSE;
        }

        WriteMapping(L"Global\\hooks");
        WriteMapping(L"Global\\toBeHooked");
    }
    return TRUE;
}

PTBHOOKED FillTBHOOKED(LPCWSTR moduleName, LPCSTR funcName, LPCWSTR callBackModuleName, LPCSTR callBackFuncName, DWORD procId, UINT64 callBackAddress, UINT64 funcAddress)
{
    PTBHOOKED tbh = new TBHOOKED;

    tbh->callBack = new char[strlen(callBackFuncName) + 1] {'\0'};
    strcpy_s((char*)tbh->callBack, strlen(callBackFuncName) + 1, callBackFuncName);

    tbh->callBackModuleName = new wchar_t[wcslen(callBackModuleName) + 1] { L'\0' };
    wcscpy_s((wchar_t*)tbh->callBackModuleName, wcslen(callBackModuleName) + 1, callBackModuleName);

    tbh->funcName = new char[strlen(funcName) + 1] { '\0' };
    strcpy_s((char*)tbh->funcName, strlen(funcName) + 1, funcName);

    tbh->moduleName = new wchar_t[wcslen(moduleName) + 1] { L'\0' };
    wcscpy_s((wchar_t*)tbh->moduleName, wcslen(moduleName) + 1, moduleName);

    tbh->procId = procId;
    tbh->callBackAddress = callBackAddress;
    tbh->funcAddress = funcAddress;

    return tbh;
}

BOOL TargetLengthIsSufficient(UINT64 funcAddress)
{
    LPBYTE p = (LPBYTE)funcAddress;
    for (int i = 0; i < sizeof(PROCHOOK); i++)
    {
        BYTE b = *(p + i);
        if (b == RETN_2 || b == RETN_3 || b == RETF_A || b == RETF_B)
            return FALSE;
    }
    return TRUE;
}

UINT64 GetCallBackAddress(LPCWSTR callBackModuleName, LPCSTR callBackFuncName)
{
    UINT64 address = 0;
    
    HMODULE hMod = GetModuleHandle(callBackModuleName);
	if (!hMod)
		hMod = LoadLibrary(callBackModuleName);
    if (!hMod)
        return FALSE;
    
    address = (UINT64)GetProcAddress(hMod, callBackFuncName);
    if (!address)
        address = GetManagedProcAddress(callBackModuleName, callBackFuncName);
	
    return address;
}

ULONG GetStealthStubSize()
{
    BYTE* Ptr;
    BYTE* BasePtr = Ptr = (BYTE*)StealthStub_ASM_x64;

    while (TRUE)
    {
        if (*((ULONG*)Ptr) == 0x12345678)
            return (ULONG)(Ptr - BasePtr);
        Ptr++;
    }

    return 0;
}

HANDLE GetTargetThread(DWORD procId)
{
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(THREADENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

    HANDLE hHijackedThread = NULL;

    if (Thread32First(snapshot, &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID == procId)
            {
                hHijackedThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
                if (!hHijackedThread)
                    continue;
                DWORD suspendCount = SuspendThread(hHijackedThread);
                if (!suspendCount && suspendCount != -1)
                {
                    CloseHandle(snapshot);
                    return hHijackedThread;
                }
            }

        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return hHijackedThread;
}

BOOL StealthLoadLibrary(HANDLE hProc, DWORD procId, LPTHREAD_START_ROUTINE InRemoteRoutine, PVOID InRemoteParam)
{
    STEALTH_CONTEXT LocalCtx{};
    memset(&LocalCtx, 0, sizeof(LocalCtx));

    HANDLE hHijackedThread = GetTargetThread(procId);
    if (!hHijackedThread)
    {
        AddLogMessage(L"Couldn't get running thread of remote process", __FILE__, __LINE__);
        return FALSE;
    }

    CONTEXT Context{};
    Context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(hHijackedThread, &Context))
    {
        AddLogMessage(L"Couldn't get remote thread context", __FILE__, __LINE__);
        CloseHandle(hHijackedThread);
        return FALSE;
    }

    LocalCtx.Rax = Context.Rax;
    LocalCtx.Rcx = Context.Rcx;
    LocalCtx.Rdx = Context.Rdx;
    LocalCtx.Rbx = Context.Rbx;
    LocalCtx.Rbp = Context.Rbp;
    LocalCtx.Rsp = Context.Rsp;
    LocalCtx.Rdi = Context.Rdi;
    LocalCtx.Rsi = Context.Rsi;
    LocalCtx.Rip = Context.Rip;
    LocalCtx.RFlags = Context.EFlags;
    LocalCtx.R8 = Context.R8;
    LocalCtx.R9 = Context.R9;
    LocalCtx.R10 = Context.R10;
    LocalCtx.R11 = Context.R11;
    LocalCtx.R12 = Context.R12;
    LocalCtx.R13 = Context.R13;
    LocalCtx.R14 = Context.R14;
    LocalCtx.R15 = Context.R15;

    LocalCtx.CreateThread = (ULONG64)CreateThread;
    LocalCtx.RemoteThreadStart = (ULONG64)InRemoteRoutine;
    LocalCtx.RemoteThreadParam = (ULONG64)InRemoteParam;
    LocalCtx.CloseHandle = (ULONG64)CloseHandle;
    LocalCtx.SetEvent = (ULONG64)SetEvent;
    LocalCtx.WaitForSingleObject = (ULONG64)WaitForSingleObject;
    LocalCtx.hThread = NULL;

    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEvent)
    {
        AddLogMessage(L"Couldn't create event", __FILE__, __LINE__);
        CloseHandle(hHijackedThread);
        return FALSE;
    }

    if (!DuplicateHandle(GetCurrentProcess(), hEvent, hProc, &LocalCtx.hEvent, 0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        AddLogMessage(L"Couldn't duplicate event handle", __FILE__, __LINE__);
        CloseHandle(hEvent);
        CloseHandle(hHijackedThread);
        return FALSE;
    }

    ULONG stubSize = GetStealthStubSize();
    ULONG CtxSize = stubSize + sizeof(LocalCtx);

    BYTE* addr = (BYTE*)VirtualAllocEx(hProc, NULL, CtxSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!addr)
    {
        AddLogMessage(L"Couldn't allocate memory for remote process", __FILE__, __LINE__);
        CloseHandle(hEvent);
        CloseHandle(hHijackedThread);
        return FALSE;
    }

    if (!WriteProcessMemory(hProc, addr + stubSize, &LocalCtx, sizeof(LocalCtx), NULL) || !WriteProcessMemory(hProc, addr, StealthStub_ASM_x64, stubSize, NULL))
    {
        AddLogMessage(L"Couldn't write to memory of remote process", __FILE__, __LINE__);
        CloseHandle(hEvent);
        CloseHandle(hHijackedThread);
        return FALSE;
    }

    Context.Rip = (UINT64)addr;
    Context.Rbx = (UINT64)addr + stubSize;

    if (!SetThreadContext(hHijackedThread, &Context))
    {
        AddLogMessage(L"Couldn't set remote thread context", __FILE__, __LINE__);
        CloseHandle(hEvent);
        CloseHandle(hHijackedThread);
        return FALSE;
    }

    ResumeThread(hHijackedThread);

    WaitForSingleObject(hEvent, INFINITE);

    if (ReadProcessMemory(hProc, addr + stubSize, &LocalCtx, sizeof(LocalCtx), NULL))
    {
        if (!LocalCtx.hThread)
        {
            AddLogMessage(L"Couldn't create remote thread", __FILE__, __LINE__);
            CloseHandle(hEvent);
            CloseHandle(hHijackedThread);
            return FALSE;
        }
    }
    else
    {
        AddLogMessage(L"Couldn't read memory of remote process", __FILE__, __LINE__);
        CloseHandle(hEvent);
        CloseHandle(hHijackedThread);
        return FALSE;
    }

    VirtualFreeEx(hProc, addr, 0, MEM_RELEASE);

    CloseHandle(hEvent);
    CloseHandle(hHijackedThread);

    return TRUE;
}

BOOL RemoteLoadLibrary(DWORD procId)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE, FALSE, procId);
    if (hProcess)
    {
        wchar_t modName[MAX_PATH]{ L'\0' };
        DWORD nameLength = GetModuleFileName(hDll, modName, MAX_PATH);
        if (!nameLength)
        {
            AddLogMessage(L"Couldn't get module name", __FILE__, __LINE__);
            return FALSE;
        }

        SIZE_T buffSize = sizeof(wchar_t) * ((SIZE_T)nameLength + 1);

        LPVOID arg = VirtualAllocEx(hProcess, NULL, buffSize, MEM_COMMIT, PAGE_READWRITE);
		if (arg && WriteProcessMemory(hProcess, arg, modName, buffSize, NULL))
		{
			if (UseStealth)
			{
				if (!StealthLoadLibrary(hProcess, procId, (LPTHREAD_START_ROUTINE)LoadLibrary, arg))
				{
                    AddLogMessage(L"Call to \"StealthLoadLibrary\" was unsuccessful", __FILE__, __LINE__);
                    CloseHandle(hProcess);
					return FALSE;
				}
                else
                    VirtualFreeEx(hProcess, arg, buffSize, MEM_FREE);
            }
			else
			{
				HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, arg, 0, NULL);
                if (hThread)
                {
                    WaitForSingleObject(hThread, INFINITE);
                    VirtualFreeEx(hProcess, arg, 0, MEM_RELEASE);
                    CloseHandle(hThread);
                }
				else
				{
                    AddLogMessage(L"Couldn't create remote thread", __FILE__, __LINE__);
                    VirtualFreeEx(hProcess, arg, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
					return FALSE;
				}
			}
        }
        else
        {
            AddLogMessage(L"Couldn't allocate memory for remote process or write to it", __FILE__, __LINE__);
            return FALSE;
        }
        CloseHandle(hProcess);
        return TRUE;
    }
    else
    {
        AddLogMessage((wstring(L"Couldn't open process with id ") + to_wstring(procId)).data(), __FILE__, __LINE__);
        return FALSE;
    }

    return FALSE;
}

BOOL IsPointerValid(PVOID ptr)
{
    WIN32_MEMORY_REGION_INFORMATION mi{};
    SIZE_T miSize = 0;
    return QueryVirtualMemoryInformation(GetCurrentProcess(), ptr, MemoryRegionInfo, &mi, sizeof(mi), &miSize);
}

BOOL SetHook(LPCWSTR moduleName, LPCSTR funcName, LPCWSTR callBackModuleName, LPCSTR callBackFuncName, DWORD procId = 0, BOOL fromCreator = TRUE, BOOL global = FALSE, UINT64 callBackAddress = NULL, UINT64 funcAddress = NULL)
{
    if (!Initialize(fromCreator))
        return FALSE;

    if (fromCreator && procId == PROCID_GLOBAL_HOOK && !hHook)
        hHook = SetWindowsHookEx(WH_GETMESSAGE, MsgHookingProc, hDll, 0);

    DWORD currProcId = (procId == PROCID_GLOBAL_HOOK ? GetCurrentProcessId() : procId);
    string key = to_string(currProcId) + ":" + (funcAddress ? to_string(funcAddress) : funcName);

    if (AreThereHooks((funcAddress ? to_string(funcAddress).data() : funcName), currProcId) || AreThereGlobalHooks((funcAddress ? to_string(funcAddress).data() : funcName), currProcId))
    {
        LPCWSTR wFuncName = a2w(funcName);
        AddLogMessage((wstring(L"Hook for \"") + wFuncName + L"\" is already set").data(), __FILE__, __LINE__);
        delete[] wFuncName;
        return FALSE;
    }

	if (procId && fromCreator)
	{
        if (procId != PROCID_GLOBAL_HOOK)
        {
            if (!RemoteLoadLibrary(procId))
            {
                AddLogMessage(L"Call to \"RemoteLoadLibrary\" was unsuccessful", __FILE__, __LINE__);
                return FALSE;
            }
        }

        PTBHOOKED tbh = FillTBHOOKED(funcAddress ? L"" : moduleName, funcAddress ? "" : funcName, callBackAddress ? L"" : callBackModuleName, callBackAddress ? "" : callBackFuncName, procId, callBackAddress, funcAddress);
		HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
        if (hMut)
        {
            if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
            {
                ReadMapping(L"Global\\toBeHooked");
                toBeHooked.push_back(tbh);
                WriteMapping(L"Global\\toBeHooked");
                ReleaseMutex(hMut);
            }
            else
            {
                AddLogMessage(L"Error waiting for mutex", __FILE__, __LINE__);
                CloseHandle(hMut);
                return FALSE;
            }
            CloseHandle(hMut);
        }
        else
        {
            AddLogMessage(L"Couldn't open mutex", __FILE__, __LINE__);
            return FALSE;
        }

		HANDLE hEvent = OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"Global\\SignalCheckHooks");
        if (hEvent)
        {
            if (!SetEvent(hEvent))
            {
                AddLogMessage(L"Couldn't set event", __FILE__, __LINE__);
                CloseHandle(hEvent);
                return FALSE;
            }
            CloseHandle(hEvent);
        }
        else
        {
            AddLogMessage(L"Couldn't open event", __FILE__, __LINE__);
            return FALSE;
        }

		return TRUE;
	}

	UINT64 hookedFunc = funcAddress ? funcAddress : GetCallBackAddress(moduleName, funcName);
    if (!hookedFunc)
    {
        AddLogMessage(L"Couldn't get function address", __FILE__, __LINE__);
        return FALSE;
    }

    if (funcAddress && !IsPointerValid((PVOID)funcAddress))
    {
        AddLogMessage(L"Passed to \"SetHook\" hooked function address is invalid", __FILE__, __LINE__);
        return FALSE;
    }

    if (!TargetLengthIsSufficient(hookedFunc))
    {
        AddLogMessage(L"Function to be hooked is too short", __FILE__, __LINE__);
        return FALSE;
    }

    UINT64 callBackFunc = callBackAddress ? callBackAddress : GetCallBackAddress(callBackModuleName, callBackFuncName);
    if (!callBackFunc)
    {
        AddLogMessage(L"Couldn't get function address", __FILE__, __LINE__);
        return FALSE;
    }

    if (callBackAddress && !IsPointerValid((PVOID)callBackAddress))
    {
        AddLogMessage(L"Passed to \"SetHook\" callback address is invalid", __FILE__, __LINE__);
        return FALSE;
    }

	PHOOKREC phr = new HOOKREC;
    if (!CreateHook(hookedFunc, callBackFunc, phr))
    {
        AddLogMessage(L"Couldn't create hook", __FILE__, __LINE__);
        return FALSE;
    }

	HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
	if (hMut)
	{
		if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
		{
			if (global)
			{
				ReadMapping(L"Global\\globalHooks");
				globalHooks.insert({ key, *phr });
				WriteMapping(L"Global\\globalHooks");
			}
			else
			{
				ReadMapping(L"Global\\hooks");
				hooks.insert({ key, *phr });
				WriteMapping(L"Global\\hooks");
			}
			ReleaseMutex(hMut);
		}
        else
        {
            AddLogMessage(L"Error waiting for mutex", __FILE__, __LINE__);
            return FALSE;
        }
		CloseHandle(hMut);
	}
    else
    {
        AddLogMessage(L"Couldn't open mutex", __FILE__, __LINE__);
        return FALSE;
    }

    delete phr;

	return TRUE;
}

void RemoveHook(LPCSTR funcName, DWORD procId = 0, UINT64 funcAddress = NULL)
{
    DWORD currProcId = GetCurrentProcessId();
    string key;

    if (!procId && creatorId && creatorId == currProcId)
        key = string("0:") + (funcAddress ? to_string(funcAddress) : funcName);
    else if (currProcId == procId)
        key = to_string(currProcId) + ":" + (funcAddress ? to_string(funcAddress) : funcName);
    else if (procId && procId != creatorId && (procId != PROCID_GLOBAL_HOOK && AreThereHooks((funcAddress ? to_string(funcAddress).data() : funcName), procId) || procId == PROCID_GLOBAL_HOOK && AreThereGlobalHooks(funcAddress ? to_string(funcAddress).data() : funcName)))
	{
		PTBHOOKED tbh = FillTBHOOKED(L"", (funcAddress ? to_string(funcAddress).data() : funcName), L"", "", procId, NULL, NULL);
		HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
		if (hMut)
		{
			if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
			{
				ReadMapping(L"Global\\toBeRemoved");
				toBeRemoved.push_back(tbh);
				WriteMapping(L"Global\\toBeRemoved");
				if (procId == PROCID_GLOBAL_HOOK)
				{
					ReadMapping(L"Global\\toBeHooked");
					for (long long i = toBeHooked.size() - 1; i >= 0; i--)
					{
						if (procId == toBeHooked[i]->procId && (funcAddress ? toBeHooked[i]->funcName == string(funcName) : toBeHooked[i]->funcAddress == funcAddress))
						{
							DeleteTBH(toBeHooked[i]);
							toBeHooked.erase(toBeHooked.begin() + i);
						}
					}
					WriteMapping(L"Global\\toBeHooked");
				}
                ReleaseMutex(hMut);
			}
            else
                AddLogMessage(L"Error waiting for mutex", __FILE__, __LINE__);
            CloseHandle(hMut);
		}
        else
            AddLogMessage(L"Couldn't open mutex", __FILE__, __LINE__);

		HANDLE hEvent = OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"Global\\SignalRemove");
		if (hEvent)
		{
			if (!SetEvent(hEvent))
                AddLogMessage(L"Couldn't set event", __FILE__, __LINE__);
			CloseHandle(hEvent);
		}
        else
            AddLogMessage(L"Couldn't open event", __FILE__, __LINE__);
	}
    else
    {
        LPWSTR wFuncName = a2w(funcName);
        AddLogMessage((wstring(L"\"RemoveHook\": no hook to remove found, funcName = ") + wFuncName + L", procId = " + to_wstring(procId)).data(), __FILE__, __LINE__);
        delete[] wFuncName;
    }

    UINT64 address = 0;
    if (key.length())
    {
        HANDLE hMut = OpenMutex(SYNCHRONIZE, FALSE, L"Global\\ReadWriteEnabled");
        if (hMut)
        {
            if (WaitForSingleObject(hMut, INFINITE) == WAIT_OBJECT_0)
            {
                ReadMapping(L"Global\\hooks");
                if (hooks.find(key) != hooks.end())
                {
                    address = hooks[key].ui64AddressShadowFunc;
                    DestroyHook(&hooks[key]);
                    hooks.erase(key);
                    WriteMapping(L"Global\\hooks");
                }
                ReadMapping(L"Global\\globalHooks");
                if (globalHooks.find(key) != globalHooks.end())
                {
                    if (!address)
                        address = hooks[key].ui64AddressShadowFunc;
                    DestroyHook(&globalHooks[key]);
                    globalHooks.erase(key);
                    WriteMapping(L"Global\\globalHooks");
                }
                ReleaseMutex(hMut);
            }
            else
                AddLogMessage(L"Error waiting for mutex", __FILE__, __LINE__);
            CloseHandle(hMut);
        }
        else
            AddLogMessage(L"Couldn't open mutex", __FILE__, __LINE__);
        
        if (key.substr(0, 2) != "0:")
        {
            if (address)
            {
                HMODULE hMod = IsModuleInUse(address);
                if (hMod)
                    FreeLibrary(hMod);
            }
            
            if (!AreThereHooks((funcAddress ? to_string(funcAddress).data() : funcName), procId) && !AreThereGlobalHooks(funcAddress ? to_string(funcAddress).data() : funcName, procId))
            {
                HANDLE hClean = OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"Global\\CleanUp");
                if (hClean)
                {
                    if (!SetEvent(hClean))
                        AddLogMessage(L"Couldn't set event", __FILE__, __LINE__);
                    CloseHandle(hClean);
                }
                else
                    AddLogMessage(L"Couldn't open event", __FILE__, __LINE__);
            }
        }
    }
}

