using System;
using System.Runtime.InteropServices;
using ExternalDotNet;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTest
{
    [TestClass]
    public class UnitTestAssembler
    {
        [TestMethod]
        public void AssemblesFunctionCall32Bit()
        {
            Assembler asm = new Assembler(false);
            asm.FunctionCall(1234567, CallingConvention.Cdecl);
            CollectionAssert.AreEqual(new byte []{ 0xB8, 0x87, 0xD6, 0x12, 0x00, 0xFF, 0xD0 }, asm.ToByteArray());
        }

        [TestMethod]
        public void AssemblesFunctionCall64Bit()
        {
            Assembler asm = new Assembler(true);
            asm.FunctionCall(1234567213123);
            CollectionAssert.AreEqual(new byte[] { 0x48, 0xB8, 0x43, 0xB0, 0xF0, 0x71, 0x1F, 0x01, 0x00, 0x00, 0xFF, 0xD0 }, asm.ToByteArray());
        }
    }
}
