using System.Runtime.InteropServices;

namespace ClassLibrary1
{
    public static class Class1
    {
        public delegate bool ShadowTerminateProcessDelegate(IntPtr handle, Int32 exitCode);
        public static bool ShadowTerminateProcess(IntPtr handle, Int32 exitCode)
        {
            //MessageBox.Show(handle.ToString());
            return true;
        }
    }
}