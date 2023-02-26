using System.Diagnostics;
using System.Runtime.InteropServices;

//bool res = AnyHook.AnyHook.SetLocalHook("kernel32.dll", "TerminateProcess", new ShadowTerminateProcessDelegate(ShadowTerminateProcess));
//Process.GetCurrentProcess().Kill();
uint id = (uint)Process.GetProcessesByName("taskmgr")[0].Id;
//bool res = AnyHook.AnyHook.SetRemoteHook("kernel32.dll", "TerminateProcess", "C:\\Users\\kacha\\source\\repos\\AnyHook\\ClassLibrary1\\bin\\Debug\\net7.0-windows10.0.22621.0\\ClassLibrary1.dll", "ShadowTerminateProcess\\ShadowTerminateProcessDelegate", id);

bool res = AnyHook.AnyHook.SetRemoteHook("kernel32.dll", "TerminateProcess", "C:\\Users\\kacha\\source\\repos\\AnyHook\\ClassLibrary1\\bin\\Debug\\net7.0\\ClassLibrary1.dll", "ShadowTerminateProcess\\ClassLibrary1.Class1+ShadowTerminateProcessDelegate", id);
Console.ReadKey();
//AnyHook.AnyHook.RemoveRemoteHook("TerminateProcess", id);

public delegate bool ShadowTerminateProcessDelegate(IntPtr handle, int exitCode);

partial class Program
{
    public static bool ShadowTerminateProcess(IntPtr handle, int exitCode)
    {
        //Console.WriteLine(handle.ToString());

        //AnyHook.AnyHook.RemoveLocalHook("TerminateProcess");
        //Process.GetCurrentProcess().Kill();
        //Console.WriteLine("!!!");
        //Console.ReadKey();

        return true;
    }
}


