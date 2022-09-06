#pragma once

#include "types.h"

using namespace std;

unordered_map<string, HOOKREC> hooks;
unordered_map<string, HOOKREC> globalHooks;

vector<PTBHOOKED> toBeHooked;
vector<PTBHOOKED> toBeRemoved;

#pragma data_seg(".shared")

DWORD creatorId = 0;
HANDLE hMapHooks = NULL;
HANDLE hMapGlobalHooks = NULL;
HANDLE hMapToBeHooked = NULL;
HANDLE hMapToBeRemoved = NULL;
HANDLE hRemove = NULL;
HANDLE hCheckHooks = NULL;
HANDLE hMutex = NULL;
HHOOK hHook = NULL;

#pragma data_seg()

BOOL removeThreadCreated = FALSE;
BOOL checkHookThreadCreated = FALSE;
BOOL UseStealth = FALSE;

HMODULE hDll;

BOOL CreateHook(unsigned __int64, unsigned __int64, PHOOKREC);
void DestroyHook(PHOOKREC);
void HookFunction(PHOOKREC);
void UnhookFunction(PHOOKREC);
BOOL SetHook(LPCWSTR, LPCSTR, LPCWSTR, LPCSTR, DWORD, BOOL, BOOL, UINT64, UINT64);
void WriteMapping(LPCWSTR);
void ReadMapping(LPCWSTR);
void RemoveHook(LPCSTR, DWORD, UINT64);
void WaitForHooks();
void WaitForRemove();
LPBYTE SerializeMap(unordered_map<string, HOOKREC>*, SIZE_T*);
unordered_map<string, HOOKREC>* DeserializeMap(LPBYTE, SIZE_T);
LPBYTE SerializeVector(vector<PTBHOOKED>, SIZE_T*);
vector<PTBHOOKED>* DeserializeVector(LPBYTE, SIZE_T);
UINT64 GetManagedProcAddress(LPCWSTR moduleName, LPCSTR funcName);
extern "C" void StealthStub_ASM_x64();
wchar_t* a2w(const char* c);
