using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ManagedShadow
{
    public class Class1
    {
        public delegate bool ShadowTerminateProcessDelegate(IntPtr handle, int exitCode);

        public static bool ShadowTerminateProcess(IntPtr handle, int exitCode)
        {
            MessageBox.Show(handle.ToString());
            return true;
        }

    }
}
