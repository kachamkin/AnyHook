#include "pch.h"
#include "types.h"

using namespace std;

LPBYTE SerializePROCHOOK(PPROCHOOK ph)
{
    LPBYTE pBuffer = (LPBYTE)malloc(sizeof(PROCHOOK));
    if (!pBuffer)
        return NULL;

    memcpy(pBuffer, ph, sizeof(PROCHOOK));

    return pBuffer;
}

PPROCHOOK DeserializePROCHOOK(LPBYTE rawData)
{
    if (!rawData)
        return NULL;

    PPROCHOOK ph = new PROCHOOK;
    memcpy(ph, rawData, sizeof(PROCHOOK));

    return ph;
}

LPBYTE SerializeHOOKREC(PHOOKREC ph)
{
    LPBYTE pBuffer = (LPBYTE)malloc(sizeof(HOOKREC));
    if (!pBuffer)
        return NULL;

    LPBYTE pNew = SerializePROCHOOK(&ph->phNew);
    if (!pNew)
        return NULL;

    LPBYTE pOld = SerializePROCHOOK(&ph->phOld);
    if (!pOld)
    {
        free(pNew);
        return NULL;
    }

    memcpy(pBuffer, pNew, sizeof(PROCHOOK));
    memcpy(pBuffer + sizeof(PROCHOOK), pOld, sizeof(PROCHOOK));
    memcpy(pBuffer + 2 * sizeof(PROCHOOK), &ph->ui64AddressFunc, sizeof(UINT64));
    memcpy(pBuffer + 2 * sizeof(PROCHOOK) + sizeof(UINT64), &ph->ui64AddressShadowFunc, sizeof(UINT64));

    free(pNew);
    free(pOld);

    return pBuffer;
}

PHOOKREC DeserializeHOOKREC(LPBYTE rawData)
{
    if (!rawData)
        return NULL;

    PPROCHOOK pNew = DeserializePROCHOOK(rawData);
    if (!pNew)
        return NULL;

    PPROCHOOK pOld = DeserializePROCHOOK(rawData + sizeof(PROCHOOK));
    if (!pOld)
    {
        delete pNew;
        return NULL;
    }

    PHOOKREC ph = new HOOKREC;
    memcpy(&ph->phNew, pNew, sizeof(PROCHOOK));
    memcpy(&ph->phOld, pOld, sizeof(PROCHOOK));
    memcpy(&ph->ui64AddressFunc, rawData + 2 * sizeof(PROCHOOK), sizeof(UINT64));
    memcpy(&ph->ui64AddressShadowFunc, rawData + 2 * sizeof(PROCHOOK) + sizeof(UINT64), sizeof(UINT64));

    delete pNew;
    delete pOld;

    return ph;
}

LPBYTE SerializeMap(unordered_map<string, HOOKREC>* pMap, SIZE_T* size)
{
    if (!pMap)
        return NULL;

    *size = 0;
    for (const pair<string, HOOKREC>& p : *pMap)
        *size += p.first.length() + sizeof(SIZE_T) + sizeof(HOOKREC);

    LPBYTE pBuffer = (LPBYTE)malloc(*size);
    if (!pBuffer)
        return NULL;

    LPBYTE pInter = pBuffer;

    for (const pair<string, HOOKREC>& p : *pMap)
    {
        LPBYTE phr = SerializeHOOKREC((PHOOKREC)&p.second);
        if (!phr)
            continue;

        SIZE_T len = p.first.length();
        memcpy(pInter, &len, sizeof(SIZE_T));
        memcpy(pInter + sizeof(SIZE_T), p.first.data(), len);
        memcpy(pInter + sizeof(SIZE_T) + len, phr, sizeof(HOOKREC));

        pInter += sizeof(SIZE_T) + len + sizeof(HOOKREC);

        free(phr);
    }

    return pBuffer;
}

unordered_map<string, HOOKREC>* DeserializeMap(LPBYTE rawData, SIZE_T toLoad)
{
    unordered_map<string, HOOKREC>* pMap = new unordered_map<string, HOOKREC>;

    SIZE_T len = 0;
    LPBYTE pInter = rawData;
    while (toLoad)
    {
        memcpy(&len, pInter, sizeof(SIZE_T));

        string key;
        key.append((char*)(pInter + sizeof(SIZE_T)), len);

        PHOOKREC ph = DeserializeHOOKREC(pInter + sizeof(SIZE_T) + len);
        if (!ph)
            return pMap;
        pMap->insert({ key, *ph });

        pInter += sizeof(SIZE_T) + len + sizeof(HOOKREC);
        toLoad -= sizeof(SIZE_T) + len + sizeof(HOOKREC);
    }

    return pMap;
}

LPBYTE SerializeTBHOOKED(PTBHOOKED pth, SIZE_T* size)
{
    *size = wcslen(pth->moduleName) * sizeof(wchar_t) +
        wcslen(pth->callBackModuleName) * sizeof(wchar_t) +
        strlen(pth->funcName) +
        strlen(pth->callBack) +
        sizeof(DWORD) +
        4 * sizeof(SIZE_T) + sizeof(BOOL) + 2 * sizeof(UINT64);

    BYTE* pBuffer = (BYTE*)malloc(*size);
    if (!pBuffer)
        return NULL;

    SIZE_T len = wcslen(pth->moduleName) * sizeof(wchar_t);
    memcpy(pBuffer, &len, sizeof(SIZE_T));
    memcpy(pBuffer + sizeof(SIZE_T), pth->moduleName, len);

    BYTE* pInter = (BYTE*)pBuffer + sizeof(SIZE_T) + len;

    len = wcslen(pth->callBackModuleName) * sizeof(wchar_t);
    memcpy(pInter, &len, sizeof(SIZE_T));
    memcpy(pInter + sizeof(SIZE_T), pth->callBackModuleName, len);

    pInter += sizeof(SIZE_T) + len;

    len = strlen(pth->funcName);
    memcpy(pInter, &len, sizeof(SIZE_T));
    memcpy(pInter + sizeof(SIZE_T), pth->funcName, len);

    pInter += sizeof(SIZE_T) + len;

    len = strlen(pth->callBack);
    memcpy(pInter, &len, sizeof(SIZE_T));
    memcpy(pInter + sizeof(SIZE_T), pth->callBack, len);

    pInter += sizeof(SIZE_T) + len;

    memcpy(pInter, &pth->procId, sizeof(DWORD));
    memcpy(pInter + sizeof(DWORD), &pth->callBackAddress, sizeof(UINT64));
    memcpy(pInter + sizeof(DWORD) + sizeof(UINT64), &pth->funcAddress, sizeof(UINT64));

    return pBuffer;
}

PTBHOOKED DeserializeTBHOOKED(LPBYTE rawData)
{
    PTBHOOKED pth = new TBHOOKED;

    SIZE_T len = 0;
    memcpy(&len, rawData, sizeof(SIZE_T));
    pth->moduleName = new wchar_t[len / sizeof(wchar_t) + 1] {L'\0'};
    memcpy((void*)pth->moduleName, rawData + sizeof(SIZE_T), len);

    BYTE* pInter = rawData + sizeof(SIZE_T) + len;

    memcpy(&len, pInter, sizeof(SIZE_T));
    pth->callBackModuleName = new wchar_t[len / sizeof(wchar_t) + 1] {L'\0'};
    memcpy((void*)pth->callBackModuleName, pInter + sizeof(SIZE_T), len);

    pInter += sizeof(SIZE_T) + len;

    memcpy(&len, pInter, sizeof(SIZE_T));
    pth->funcName = new char[len + 1] { '\0' };
    memcpy((void*)pth->funcName, pInter + sizeof(SIZE_T), len);

    pInter += sizeof(SIZE_T) + len;

    memcpy(&len, pInter, sizeof(SIZE_T));
    pth->callBack = new char[len + 1] { '\0' };
    memcpy((void*)pth->callBack, pInter + sizeof(SIZE_T), len);

    pInter += sizeof(SIZE_T) + len;

    memcpy(&pth->procId, pInter, sizeof(DWORD));
    memcpy(&pth->callBackAddress, pInter + sizeof(DWORD), sizeof(UINT64));
    memcpy(&pth->funcAddress, pInter + sizeof(DWORD) + sizeof(UINT64), sizeof(UINT64));

    return pth;
}

LPBYTE SerializeVector(vector<PTBHOOKED>* v, SIZE_T* size)
{
    LPBYTE* structs = new LPBYTE[v->size()];
    SIZE_T* sizes = new SIZE_T[v->size()];

    SIZE_T total = 0;

    for (size_t i = 0; i < v->size(); i++)
    {
        structs[i] = SerializeTBHOOKED((*v)[i], &sizes[i]);
        if (!structs[i])
            continue;
        total += sizes[i];
    }

    *size = total + v->size() * sizeof(SIZE_T);
    LPBYTE pVector = (LPBYTE)malloc(*size);
    if (!pVector)
    {
        delete[] structs;
        delete[] sizes;
        return NULL;
    }

    LPBYTE pInter = pVector;

    for (size_t i = 0; i < v->size(); i++)
    {
        memcpy(pInter, &sizes[i], sizeof(SIZE_T));
        memcpy(pInter + sizeof(SIZE_T), structs[i], sizes[i]);
        pInter += sizes[i] + sizeof(SIZE_T);
        free(structs[i]);
    }

    delete[] structs;
    delete[] sizes;

    return pVector;
}

vector<PTBHOOKED>* DeserializeVector(LPBYTE rawData, SIZE_T toLoad)
{
    vector<PTBHOOKED>* pVector = new vector<PTBHOOKED>;
    if (!rawData)
        return pVector;

    SIZE_T len = 0;
    LPBYTE pInter = rawData;
    while (toLoad)
    {
        memcpy(&len, pInter, sizeof(SIZE_T));
        PTBHOOKED ptb = DeserializeTBHOOKED(pInter + sizeof(SIZE_T));
        if (!ptb)
            return pVector;
        pVector->push_back(ptb);
        pInter += len + sizeof(SIZE_T);
        toLoad -= len + sizeof(SIZE_T);
    }

    return pVector;
}