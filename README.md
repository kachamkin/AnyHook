# AnyHook

This library gives you a possibility to hook any Windows x64 functions from any code:
native C++, managed .NET Framework and managed .NET Core (.NET 6.0).
You can set local hooks (hooking functions calls of local process), remote hooks (hooking functions calls of remote process by process ID)
and global hooks (hooking functions calls of any process which uses Windows GetMessage call).
Callback functions could be set by their addresses, names (module name plus function name) and as delegate instances (managed code).

C# example (.NET 6.0)

using System.Diagnostics;

AnyHook.AnyHook.SetLocalHook("kernel32.dll", "TerminateProcess", new ShadowTerminateProcessDelegate(ShadowTerminateProcess));
Process.GetCurrentProcess().Kill();
Console.ReadKey();

public delegate bool ShadowTerminateProcessDelegate(IntPtr handle, int exitCode);

partial class Program
{
	public static bool ShadowTerminateProcess(IntPtr handle, int exitCode)
	{
		Console.WriteLine(handle.ToString());
		return true;
	}
}

C++ example (native)

__declspec(dllimport) extern BOOL SetRemoteHook(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD);

int wmain()
{
    SetRemoteHook(L"kernel32.dll", L"TerminateProcess", "C:\Users\kacha\source\repos\AnyHook\ManagedShadow\bin\Debug\ManagedShadow.dll", L"ShadowTerminateProcess", 8780);
    TerminateProcess(GetCurrentProcess(), 0);
    WaitForSingleObject(GetCurrentProcess(), INFINITE);
    return 0;
}

Author parially used ideas proposed and implemented:

1) here: https://github.com/EasyHook/EasyHook
2) and here: https://github.com/williammortl/Prochook64
