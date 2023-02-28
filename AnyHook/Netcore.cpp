#include "pch.h"
#include "types.h"
#include "nethost.h"
#include "core_clrdelegates.h"
#include "hostfxr.h"

using namespace std;

void AddLogMessage(LPCWSTR message, LPCSTR file, int line, BOOL bError = TRUE);

hostfxr_initialize_for_runtime_config_fn init_fptr;
hostfxr_get_runtime_delegate_fn get_delegate_fptr;
hostfxr_close_fn close_fptr;

bool load_hostfxr()
{
    char_t buffer[MAX_PATH];
    size_t buffer_size = sizeof(buffer) / sizeof(char_t);
    if (get_hostfxr_path(buffer, &buffer_size, nullptr))
        return false;

    HMODULE lib = LoadLibrary(buffer);
    if (!lib)
        return false;

    init_fptr = (hostfxr_initialize_for_runtime_config_fn)GetProcAddress(lib, "hostfxr_initialize_for_runtime_config");
    get_delegate_fptr = (hostfxr_get_runtime_delegate_fn)GetProcAddress(lib, "hostfxr_get_runtime_delegate");
    close_fptr = (hostfxr_close_fn)GetProcAddress(lib, "hostfxr_close");

    return (init_fptr && get_delegate_fptr && close_fptr);
}

load_assembly_and_get_function_pointer_fn get_dotnet_load_assembly(const char_t* config_path)
{
    void* load_assembly_and_get_function_pointer = nullptr;
    hostfxr_handle cxt = nullptr;
    if (init_fptr(config_path, nullptr, &cxt) || !cxt)
    {
        AddLogMessage(L".NET init failed", __FILE__, __LINE__);
        close_fptr(cxt);
        return nullptr;
    }

    if (get_delegate_fptr(
        cxt,
        hdt_load_assembly_and_get_function_pointer,
        &load_assembly_and_get_function_pointer) || !load_assembly_and_get_function_pointer)
        AddLogMessage(L"Get delegate failed", __FILE__, __LINE__);

    close_fptr(cxt);
    return (load_assembly_and_get_function_pointer_fn)load_assembly_and_get_function_pointer;
}

UINT64 GetDotNetManagedProcAddress(LPCWSTR moduleName, LPCWSTR funcName, LPCWSTR delegateName)
{
    if (!load_hostfxr())
    {
        AddLogMessage(L"Failure: load_hostfxr()", __FILE__, __LINE__);
        return 0;
    }

    wstring shortName = moduleName;
    size_t pos = shortName.rfind(L"\\");
    if (pos == wstring::npos)
    {
        AddLogMessage(L"Failed to get module name", __FILE__, __LINE__);
        return 0;
    }

    wstring dirName = shortName.substr(0, pos + 1);
    shortName = shortName.substr(pos + 1);
    pos = shortName.rfind(L".");
    if (pos != wstring::npos)
        shortName = shortName.substr(0, pos);

    load_assembly_and_get_function_pointer_fn load_assembly_and_get_function_pointer = get_dotnet_load_assembly((dirName + shortName + L".runtimeconfig.json").c_str());
    if (!load_assembly_and_get_function_pointer)
    {
        AddLogMessage(L"Failure: get_dotnet_load_assembly()", __FILE__, __LINE__);
        return 0;
    }

    wstring delName = delegateName;
    pos = delName.find(L".");
    if (pos == wstring::npos)
    {
        AddLogMessage(L"Invalid delegate name", __FILE__, __LINE__);
        return 0;
    }

    size_t pos1 = delName.find(L"+");
    if (pos1 == wstring::npos)
    {
        AddLogMessage(L"Invalid delegate name", __FILE__, __LINE__);
        return 0;
    }

    component_entry_point_fn addr = nullptr;
    load_assembly_and_get_function_pointer(
        moduleName,
        (shortName + L"." + delName.substr(pos + 1, pos1 - pos - 1) + L", " + shortName).c_str(),
        funcName,
        (wstring(delegateName) + L", " + shortName).c_str(),
        nullptr,
        (void**)&addr);

    return (UINT64)addr;
}