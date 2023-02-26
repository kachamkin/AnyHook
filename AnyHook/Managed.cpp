#include <msclr\marshal.h>
#include "nethost.h"
#include "core_clrdelegates.h"
#include "hostfxr.h"
#include <string>

using namespace std;
using namespace System;
using namespace System::Collections::Generic;
using namespace System::Reflection;
using namespace System::Runtime::InteropServices;
using namespace msclr::interop;

BOOL SetLocalHook(LPCWSTR moduleName, LPCWSTR funcName, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName);
BOOL SetGlobalHook(LPCWSTR moduleName, LPCWSTR funcName, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName);
BOOL SetRemoteHook(LPCWSTR moduleName, LPCWSTR funcName, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName, DWORD procId);
void RemoveLocalHook(LPCWSTR funcName);
void RemoveGlobalHook(LPCWSTR funcName);
void RemoveRemoteHook(LPCWSTR funcName, DWORD procId);
BOOL SetLocalHook(LPCWSTR moduleName, LPCWSTR funcName, UINT64 callBackAddress);
BOOL SetGlobalHook(LPCWSTR moduleName, LPCWSTR funcName, UINT64 callBackAddress);
BOOL SetRemoteHook(LPCWSTR moduleName, LPCWSTR funcName, DWORD procId, UINT64 callBackAddress);
BOOL SetLocalHook(UINT64 funcAddress, UINT64 callBackAddress);
BOOL SetGlobalHook(UINT64 funcAddress, UINT64 callBackAddress);
BOOL SetRemoteHook(UINT64 funcAddress, DWORD procId, UINT64 callBackAddress);
void RemoveLocalHook(UINT64 funcAddress);
void RemoveGlobalHook(UINT64 funcAddress);
void RemoveRemoteHook(UINT64 funcAddress, DWORD procId);
BOOL SetLocalHook(UINT64 funcAddress, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName);
BOOL SetGlobalHook(UINT64 funcAddress, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName);
BOOL SetRemoteHook(UINT64 funcAddress, LPCWSTR callBackModuleName, LPCWSTR callBackFuncName, DWORD procId);
void AddLogMessage(LPCWSTR message, LPCSTR file, int line, BOOL bError = TRUE);

extern BOOL UseStealth;

hostfxr_initialize_for_runtime_config_fn init_fptr;
hostfxr_get_runtime_delegate_fn get_delegate_fptr;
hostfxr_close_fn close_fptr;

bool load_hostfxr()
{
    char_t buffer[MAX_PATH];
    size_t buffer_size = sizeof(buffer) / sizeof(char_t);
    if (get_hostfxr_path(buffer, &buffer_size, nullptr) != 0)
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
    int rc = init_fptr(config_path, nullptr, &cxt);
    if (rc != 0 || cxt == nullptr)
    {
        AddLogMessage(L".NET init failed", __FILE__, __LINE__);
        close_fptr(cxt);
        return nullptr;
    }

    rc = get_delegate_fptr(
        cxt,
        hdt_load_assembly_and_get_function_pointer,
        &load_assembly_and_get_function_pointer);
    if (rc != 0 || load_assembly_and_get_function_pointer == nullptr)
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

    wstring config_path = dirName + shortName + L".runtimeconfig.json";
    
    load_assembly_and_get_function_pointer_fn load_assembly_and_get_function_pointer = nullptr;
    load_assembly_and_get_function_pointer = get_dotnet_load_assembly(config_path.c_str());
    if (load_assembly_and_get_function_pointer == nullptr)
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

    wstring dotnet_type = delName.substr(pos + 1, pos1 - pos - 1);

    component_entry_point_fn addr = nullptr;
    load_assembly_and_get_function_pointer(
        moduleName,
        (shortName + L"." + dotnet_type + L", " + shortName).c_str(),
        funcName,
        (wstring(delegateName) + L", " + shortName).c_str(),
        nullptr,
        (void**)&addr);

    return (UINT64)addr;
}

namespace AnyHook
{
    public ref class AnyHook
    {
    internal:
        
        static List<Assembly^>^ assm = gcnew List<Assembly^>(1);

        static UINT64 GetPointer(Delegate^ callBackAddress)
        {
            IntPtr ptr = IntPtr::Zero;
            marshal_context^ context = gcnew marshal_context();
            try
            {
                ptr = Marshal::GetFunctionPointerForDelegate(callBackAddress);
            }
            catch (Exception^ ex)
            {
                AddLogMessage(context->marshal_as<const wchar_t*>(ex->Message), __FILE__, __LINE__);
            }
            return ptr.ToInt64();
        }

    public:

        static property bool UseStealth
        {
            bool get() { return ::UseStealth; };
            void set(bool value) { ::UseStealth = value; };
        };

        static bool SetLocalHook(String^ moduleName, String^ funcName, String^ callBackModuleName, String^ callBackFuncName)
        {
            marshal_context^ context = gcnew marshal_context();
            return ::SetLocalHook(context->marshal_as<const wchar_t*>(moduleName), context->marshal_as<const wchar_t*>(funcName), context->marshal_as<const wchar_t*>(callBackModuleName), context->marshal_as<const wchar_t*>(callBackFuncName));
        }

        static bool SetLocalHook(IntPtr funcAddress, String^ callBackModuleName, String^ callBackFuncName)
        {
            marshal_context^ context = gcnew marshal_context();
            return ::SetLocalHook(funcAddress.ToInt64(), context->marshal_as<const wchar_t*>(callBackModuleName), context->marshal_as<const wchar_t*>(callBackFuncName));
        }

        static bool SetLocalHook(String^ moduleName, String^ funcName, IntPtr callBackAddress)
        {
            marshal_context^ context = gcnew marshal_context();
            return ::SetLocalHook(context->marshal_as<const wchar_t*>(moduleName), context->marshal_as<const wchar_t*>(funcName), callBackAddress.ToInt64());
        }

        static bool SetLocalHook(String^ moduleName, String^ funcName, Delegate^ callBackAddress)
        {
            UINT64 ptr = GetPointer(callBackAddress);
            if (!ptr)
                return false;

            marshal_context^ context = gcnew marshal_context();
            return ::SetLocalHook(context->marshal_as<const wchar_t*>(moduleName), context->marshal_as<const wchar_t*>(funcName), ptr);
        }

        static bool SetLocalHook(IntPtr funcAddress, IntPtr callBackAddress)
        {
            return ::SetLocalHook(funcAddress.ToInt64(), callBackAddress.ToInt64());
        }

        static bool SetLocalHook(IntPtr funcAddress, Delegate^ callBackAddress)
        {
            UINT64 ptr = GetPointer(callBackAddress);
            if (!ptr)
                return false;

            return ::SetLocalHook(funcAddress.ToInt64(), ptr);
        }

        static bool SetGlobalHook(String^ moduleName, String^ funcName, String^ callBackModuleName, String^ callBackFuncName)
        {
            marshal_context^ context = gcnew marshal_context();
            return ::SetGlobalHook(context->marshal_as<const wchar_t*>(moduleName), context->marshal_as<const wchar_t*>(funcName), context->marshal_as<const wchar_t*>(callBackModuleName), context->marshal_as<const wchar_t*>(callBackFuncName));
        }

        static bool SetGlobalHook(IntPtr funcAddress, String^ callBackModuleName, String^ callBackFuncName)
        {
            marshal_context^ context = gcnew marshal_context();
            return ::SetGlobalHook(funcAddress.ToInt64(), context->marshal_as<const wchar_t*>(callBackModuleName), context->marshal_as<const wchar_t*>(callBackFuncName));
        }

        static bool SetGlobalHook(String^ moduleName, String^ funcName, IntPtr callBackAddress)
        {
            marshal_context^ context = gcnew marshal_context();
            return ::SetGlobalHook(context->marshal_as<const wchar_t*>(moduleName), context->marshal_as<const wchar_t*>(funcName), callBackAddress.ToInt64());
        }

        static bool SetGlobalHook(String^ moduleName, String^ funcName, Delegate^ callBackAddress)
        {
            UINT64 ptr = GetPointer(callBackAddress);
            if (!ptr)
                return false;

            marshal_context^ context = gcnew marshal_context();
            return ::SetGlobalHook(context->marshal_as<const wchar_t*>(moduleName), context->marshal_as<const wchar_t*>(funcName), ptr);
        }

        static bool SetGlobalHook(IntPtr funcAddress, IntPtr callBackAddress)
        {
            return ::SetGlobalHook(funcAddress.ToInt64(), callBackAddress.ToInt64());
        }

        static bool SetGlobalHook(IntPtr funcAddress, Delegate^ callBackAddress)
        {
            UINT64 ptr = GetPointer(callBackAddress);
            if (!ptr)
                return false;

            return ::SetGlobalHook(funcAddress.ToInt64(), ptr);
        }

        static bool SetRemoteHook(String^ moduleName, String^ funcName, String^ callBackModuleName, String^ callBackFuncName, unsigned long procId)
        {
            marshal_context^ context = gcnew marshal_context();
            return ::SetRemoteHook(context->marshal_as<const wchar_t*>(moduleName), context->marshal_as<const wchar_t*>(funcName), context->marshal_as<const wchar_t*>(callBackModuleName), context->marshal_as<const wchar_t*>(callBackFuncName), procId);
        }

        static bool SetRemoteHook(IntPtr funcAddress, String^ callBackModuleName, String^ callBackFuncName, unsigned long procId)
        {
            marshal_context^ context = gcnew marshal_context();
            return ::SetRemoteHook(funcAddress.ToInt64(), context->marshal_as<const wchar_t*>(callBackModuleName), context->marshal_as<const wchar_t*>(callBackFuncName), procId);
        }

        static bool SetRemoteHook(String^ moduleName, String^ funcName, unsigned long procId, IntPtr callBackAddress)
        {
            marshal_context^ context = gcnew marshal_context();
            return ::SetRemoteHook(context->marshal_as<const wchar_t*>(moduleName), context->marshal_as<const wchar_t*>(funcName), procId, callBackAddress.ToInt64());
        }

        static bool SetRemoteHook(String^ moduleName, String^ funcName, unsigned long procId, Delegate^ callBackAddress)
        {
            UINT64 ptr = GetPointer(callBackAddress);
            if (!ptr)
                return false;

            marshal_context^ context = gcnew marshal_context();
            return ::SetRemoteHook(context->marshal_as<const wchar_t*>(moduleName), context->marshal_as<const wchar_t*>(funcName), procId, ptr);
        }

        static bool SetRemoteHook(IntPtr funcAddress, unsigned long procId, IntPtr callBackAddress)
        {
            return ::SetRemoteHook(funcAddress.ToInt64(), procId, callBackAddress.ToInt64());
        }

        static bool SetRemoteHook(IntPtr funcAddress, unsigned long procId, Delegate^ callBackAddress)
        {
            UINT64 ptr = GetPointer(callBackAddress);
            if (!ptr)
                return false;

            return ::SetRemoteHook(funcAddress.ToInt64(), procId, ptr);
        }

        static void RemoveLocalHook(String^ funcName)
        {
            marshal_context^ context = gcnew marshal_context();
            ::RemoveLocalHook(context->marshal_as<const wchar_t*>(funcName));
        }

        static void RemoveLocalHook(IntPtr funcAddress)
        {
            ::RemoveLocalHook(funcAddress.ToInt64());
        }

        static void RemoveGlobalHook(String^ funcName)
        {
            marshal_context^ context = gcnew marshal_context();
            ::RemoveGlobalHook(context->marshal_as<const wchar_t*>(funcName));
        }

        static void RemoveGlobalHook(IntPtr funcAddress)
        {
            ::RemoveGlobalHook(funcAddress.ToInt64());
        }

        static void RemoveRemoteHook(String^ funcName, unsigned long procId)
        {
            marshal_context^ context = gcnew marshal_context();
            ::RemoveRemoteHook(context->marshal_as<const wchar_t*>(funcName), procId);
        }

        static void RemoveRemoteHook(IntPtr funcAddress, unsigned long procId)
        {
            ::RemoveRemoteHook(funcAddress.ToInt64(), procId);
        }
    };
}

Assembly^ Resolve(Object^ source, ResolveEventArgs^ e)
{
    return AnyHook::AnyHook::assm[AnyHook::AnyHook::assm->Count - 1];
}

UINT64 GetManagedProcAddress(LPCWSTR moduleName, LPCSTR funcName)
{
    UINT64 ret = 0;
    marshal_context^ context = gcnew marshal_context();
    String^ sFuncName = gcnew String(funcName);
    String^ delegateName = "";

    try
    {
        int pos = sFuncName->IndexOf("\\");
        delegateName = sFuncName->Substring(pos + 1);
        sFuncName = sFuncName->Substring(0, pos);

        AnyHook::AnyHook::assm->Add(Assembly::LoadFile(gcnew String(moduleName)));
        AppDomain::CurrentDomain->AssemblyResolve += gcnew ResolveEventHandler(&Resolve);

        for each (Type^ t in AnyHook::AnyHook::assm[AnyHook::AnyHook::assm->Count - 1]->GetTypes())
        {
            MethodInfo^ method = t->GetMethod(sFuncName);
            if (method != nullptr)
                if (method->IsPublic && method->IsStatic)
                {
                    String^ aqn = t->AssemblyQualifiedName;
                    return (long long)Marshal::GetFunctionPointerForDelegate(Delegate::CreateDelegate(Type::GetType(aqn->Insert(aqn->IndexOf(","), "+" + delegateName)), method));
                }
        }
    }
    catch (Exception^ ex)
    {
        AddLogMessage(context->marshal_as<const wchar_t*>(ex->Message), __FILE__, __LINE__);
    }

    if (!ret)
        return GetDotNetManagedProcAddress(moduleName, context->marshal_as<const wchar_t*>(sFuncName), context->marshal_as<const wchar_t*>(delegateName));
}

void FreeManagedLibrary()
{
    marshal_context^ context = gcnew marshal_context();
    try
    {
        for each (Assembly^ a in AnyHook::AnyHook::assm)
        {
            HMODULE hMod = GetModuleHandle(context->marshal_as<const wchar_t*>(a->Location));
            if (hMod)
                FreeLibrary(hMod);
        }
    }
    catch (Exception^ ex)
    {
        AddLogMessage(context->marshal_as<const wchar_t*>(ex->Message), __FILE__, __LINE__);
    }
}