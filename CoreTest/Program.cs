// See https://aka.ms/new-console-template for more information
using System.Diagnostics;

bool res = AnyHook.AnyHook.SetLocalHook("kernel32.dll", "TerminateProcess", new ShadowTerminateProcessDelegate(ShadowTerminateProcess));
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


