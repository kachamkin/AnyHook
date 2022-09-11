﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ManagedShadow
{
    public class Class1
    {
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool ShadowTerminateProcessDelegate(IntPtr handle, Int32 exitCode);

        [return: MarshalAs(UnmanagedType.Bool)]
        public static bool ShadowTerminateProcess(IntPtr handle, Int32 exitCode)
        {
            MessageBox.Show(handle.ToString());
            return true;
        }

    }
}
