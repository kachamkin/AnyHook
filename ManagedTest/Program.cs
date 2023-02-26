using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ManagedTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //ShadowTerminateProcessDelegate stp = ShadowTerminateProcess;
            uint id = (uint)Process.GetProcessesByName("taskmgr")[0].Id;

            bool res = AnyHook.AnyHook.SetRemoteHook("kernel32.dll", "TerminateProcess", "C:\\Users\\kacha\\source\\repos\\AnyHook\\ManagedShadow\\bin\\x64\\Debug\\ManagedShadow.dll", "ShadowTerminateProcess\\ShadowTerminateProcessDelegate", id);
            //Process.GetCurrentProcess().Kill();
            Console.ReadKey(); 
        }

        public delegate bool ShadowTerminateProcessDelegate(IntPtr handle, int exitCode);

        public static bool ShadowTerminateProcess(IntPtr handle, int exitCode)
        {
            MessageBox.Show(handle.ToString());
            return true;
        }
    }
}
