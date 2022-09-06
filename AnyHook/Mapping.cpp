#include "pch.h"
#include "types.h"

using namespace std;

extern HANDLE hMapHooks;
extern HANDLE hMapGlobalHooks;
extern HANDLE hMapToBeHooked;
extern HANDLE hMapToBeRemoved;

extern unordered_map<string, HOOKREC> hooks;
extern unordered_map<string, HOOKREC> globalHooks;

extern vector<PTBHOOKED> toBeHooked;
extern vector<PTBHOOKED> toBeRemoved;

LPBYTE SerializeMap(unordered_map<string, HOOKREC>*, SIZE_T*);
unordered_map<string, HOOKREC>* DeserializeMap(LPBYTE, SIZE_T);
LPBYTE SerializeVector(vector<PTBHOOKED>*, SIZE_T*);
vector<PTBHOOKED>* DeserializeVector(LPBYTE, SIZE_T);

void WriteMapping(LPCWSTR name)
{
    BOOL ItsHooks = name == wstring(L"Global\\hooks");
    BOOL ItsGlobalHooks = name == wstring(L"Global\\globalHooks");
    BOOL ItsRemove = name == wstring(L"Global\\toBeRemoved");

    if (ItsHooks)
    {
        hMapHooks = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MAX_MAP_BUFF_SIZE, name);
        if (!hMapHooks)
            hMapHooks = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!hMapHooks)
            return;
    }
    else if (ItsGlobalHooks)
    {
        hMapGlobalHooks = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MAX_MAP_BUFF_SIZE, name);
        if (!hMapGlobalHooks)
            hMapGlobalHooks = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!hMapGlobalHooks)
            return;
    }
    else if (ItsRemove)
    {
        hMapToBeRemoved = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MAX_MAP_BUFF_SIZE, name);
        if (!hMapToBeRemoved)
            hMapToBeRemoved = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!hMapToBeRemoved)
            return;
    }
    else
    {
        hMapToBeHooked = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MAX_MAP_BUFF_SIZE, name);
        if (!hMapToBeHooked)
            hMapToBeHooked = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!hMapToBeHooked)
            return;
    }

    LPBYTE ppBuff = NULL;
    SIZE_T size = 0;
    ppBuff = ItsHooks ? SerializeMap(&hooks, &size) : (ItsGlobalHooks ? SerializeMap(&globalHooks, &size) : (ItsRemove ? SerializeVector(&toBeRemoved, &size) : SerializeVector(&toBeHooked, &size)));
    if (!ppBuff)
        return;

    LPVOID pBuff = MapViewOfFile(ItsHooks ? hMapHooks : (ItsGlobalHooks ? hMapGlobalHooks : (ItsRemove ? hMapToBeRemoved : hMapToBeHooked)), FILE_MAP_ALL_ACCESS, 0, 0, size + sizeof(SIZE_T));
    if (!pBuff)
        return;

    memcpy(pBuff, &size, sizeof(SIZE_T));
    memcpy((LPBYTE)pBuff + sizeof(SIZE_T), ppBuff, size);
    free(ppBuff);

    UnmapViewOfFile(pBuff);
}

void ReadMapping(LPCWSTR name)
{
    BOOL ItsHooks = name == wstring(L"Global\\hooks");
    BOOL ItsGlobalHooks = name == wstring(L"Global\\globalHooks");
    BOOL ItsRemove = name == wstring(L"Global\\toBeRemoved");

    if (!(ItsHooks ? hMapHooks : (ItsGlobalHooks ? hMapGlobalHooks : (ItsRemove ? hMapToBeRemoved : hMapToBeHooked))))
        return;

    HANDLE hh = OpenFileMapping(FILE_MAP_READ, FALSE, name);
    if (!hh)
        return;

    SIZE_T bufSize = 0;
    LPVOID pBuff = MapViewOfFile(hh, FILE_MAP_READ, 0, 0, sizeof(SIZE_T));
    if (!pBuff)
    {
        CloseHandle(hh);
        return;
    }

    memcpy(&bufSize, pBuff, sizeof(SIZE_T));
    UnmapViewOfFile(pBuff);

    pBuff = MapViewOfFile(hh, FILE_MAP_READ, 0, 0, bufSize + sizeof(SIZE_T));
    if (!pBuff)
    {
        CloseHandle(hh);
        return;
    }

    if (ItsHooks)
    {
        unordered_map<string, HOOKREC>* pMap = DeserializeMap((LPBYTE)pBuff + sizeof(SIZE_T), bufSize);
        if (pMap)
        {
            hooks = *pMap;
            delete pMap;
        }
    }
    else if (ItsGlobalHooks)
    {
        unordered_map<string, HOOKREC>* pMap = DeserializeMap((LPBYTE)pBuff + sizeof(SIZE_T), bufSize);
        if (pMap)
        {
            globalHooks = *pMap;
            delete pMap;
        }
    }
    else if (ItsRemove)
    {
        vector<PTBHOOKED>* pVector = DeserializeVector((LPBYTE)pBuff + sizeof(SIZE_T), bufSize);
        if (pVector)
        {
            toBeRemoved = *pVector;
            delete pVector;
        }
    }
    else
    {
        vector<PTBHOOKED>* pVector = DeserializeVector((LPBYTE)pBuff + sizeof(SIZE_T), bufSize);
        if (pVector)
        {
            toBeHooked = *pVector;
            delete pVector;
        }
    }

    UnmapViewOfFile(pBuff);
    CloseHandle(hh);
}
