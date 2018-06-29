using System;
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
                throw new AssertFailedException("No exception was thrown with invalid process name.");
            }
            catch (ArgumentException)
            {
                return;
            }
        }
    }
}
