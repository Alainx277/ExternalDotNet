using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ExternalDotNet;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTest
{
    [TestClass]
    public class UnitTestExternal
    {
        [TestMethod]
        public void ThrowExceptionOnInvalidProcessName()
        {
            try
            {
                External ex = new External("jdlkajdlkaä$awäd$üfa$ä");
                throw new AssertFailedException();
            }
            catch (ArgumentException e)
            {
                return;
            }
        }

        [TestMethod]
        public void OpenProcess()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("notepad.exe")
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process proc = new Process {StartInfo = startInfo};
            proc.Start();

            External ex = new External(proc);
            ex.OpenProcess(Native.ProcessAccessFlags.All);

            proc.Kill();
        }

        [TestMethod]
        public void GetModuleExports()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("notepad.exe")
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process proc = new Process { StartInfo = startInfo };
            proc.Start();

            External ex = new External(proc);
            ex.OpenProcess(Native.ProcessAccessFlags.All);

            Assert.IsFalse(ex.GetModuleExports("kernel32").Count == 0); 

            proc.Kill();
        }

        [TestMethod]
        public void GetModules()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("notepad.exe")
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process proc = new Process { StartInfo = startInfo };
            proc.Start();

            External ex = new External(proc);
            ex.OpenProcess(Native.ProcessAccessFlags.All);

            Assert.IsFalse(ex.GetModuleNames().Count == 0);

            proc.Kill();
        }

        [TestMethod]
        public void HasModule()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("notepad.exe")
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process proc = new Process { StartInfo = startInfo };
            proc.Start();

            External ex = new External(proc);
            ex.OpenProcess(Native.ProcessAccessFlags.All);

            Assert.IsTrue(ex.HasModule("kernel32.dll"));

            proc.Kill();
        }

        [TestMethod]
        public void HasModuleRegex()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("notepad.exe")
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process proc = new Process { StartInfo = startInfo };
            proc.Start();

            External ex = new External(proc);
            ex.OpenProcess(Native.ProcessAccessFlags.All);

            Assert.IsTrue(ex.HasModule(new Regex(@"^kernel", RegexOptions.IgnoreCase)));

            proc.Kill();
        }

        /*[TestMethod]
        public void RemoteFunctionCall()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo("notepad.exe")
            {
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process proc = new Process { StartInfo = startInfo };
            proc.Start();

            External ex = new External(proc);
            ex.OpenProcess(Native.ProcessAccessFlags.All);

            ex.ExecuteAndWait(ex.GetModuleExports("user32.dll")["MessageBoxW"], CallingConvention.Winapi, IntPtr.Zero,
                ex.AllocateAndWrite(Encoding.Unicode.GetBytes("BOI THIS SHIT WORKS")),
                ex.AllocateAndWrite(Encoding.Unicode.GetBytes("COOL TITLE")), IntPtr.Zero).Wait(5000);

            proc.Kill();
        }*/
    }
}
