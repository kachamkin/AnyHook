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
            bool res = AnyHook.AnyHook.SetLocalHook("kernel32.dll", "TerminateProcess", new ShadowTerminateProcessDelegate(ShadowTerminateProcess));
            Process.GetCurrentProcess().Kill();
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
