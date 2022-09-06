#pragma once
#include <string>
#include <unordered_map>
#include <Windows.h>
#include <tlhelp32.h>

#define PROCID_GLOBAL_HOOK 0xFFFFFFFF
#define MAX_MAP_BUFF_SIZE 0xFFFF
#define JUMP 0x25FF
#define RETN_3 0xC3
#define RETN_2 0xC2
#define RETF_A 0xCA
#define RETF_B 0xCB

#pragma pack(1)
typedef struct _ProcHook
{
    WORD jump = JUMP; 
    DWORD offset = 0;
    unsigned __int64 address;
} PROCHOOK, * PPROCHOOK;
#pragma pack()

typedef struct _HookRec
{
    unsigned __int64	ui64AddressFunc;
    unsigned __int64	ui64AddressShadowFunc;
    PROCHOOK			phOld;
    PROCHOOK			phNew;
} HOOKREC, * PHOOKREC;

typedef struct ToBeHooked
{
    LPCWSTR moduleName;
    LPCWSTR callBackModuleName;
    LPCSTR funcName;
    LPCSTR callBack;
    DWORD procId;
    UINT64 funcAddress = NULL;
    UINT64 callBackAddress = NULL;
} TBHOOKED, * PTBHOOKED;

#pragma pack(1)
typedef struct _STEALTH_CONTEXT_
{
            UINT64      CreateThread;
            UINT64      RemoteThreadStart;
            UINT64      RemoteThreadParam;
            UINT64      WaitForSingleObject;
            UINT64      SetEvent;
            UINT64      CloseHandle;
            HANDLE      hEvent;
            HANDLE      hThread;


    UINT64           Rax;		// 0
    UINT64           Rcx;		// 1
    UINT64           Rdx;		// 2
    UINT64           Rbp;		// 3
    UINT64           Rsp;		// 4
    UINT64           Rsi;		// 5
    UINT64           Rdi;		// 6
    UINT64           Rbx;		// 7
    UINT64           Rip;		// 8
    UINT64           RFlags;    // 9
    UINT64           R8;		// 10
    UINT64           R9;		// 11
    UINT64           R10;		// 12
    UINT64           R11;		// 13
    UINT64           R12;		// 14
    UINT64           R13;		// 15
    UINT64           R14;		// 16
    UINT64           R15;		// 17
}STEALTH_CONTEXT, * PSTEALTH_CONTEXT;
#pragma pack()

