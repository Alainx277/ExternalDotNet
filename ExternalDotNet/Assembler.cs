using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ExternalDotNet
{
    // Credits to bineyy for base class https://github.com/bineyy/SharpMonoInjector/blob/master/SharpMonoInjector/Injection/Assembler.cs
    // This class was extended with additional features
    public class Assembler
    {
        private readonly List<byte> _asm = new List<byte>();
        private readonly bool _is64Bit = false;

        public Assembler()
        {
        }

        public Assembler(bool is64Bit)
        {
            _is64Bit = is64Bit;
        }

        public void MovRax(Int64 arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0xB8 });
            _asm.AddRange(BitConverter.GetBytes(arg));
        }

        public void MovRcx(Int64 arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0xB9 });
            _asm.AddRange(BitConverter.GetBytes(arg));
        }

        public void MovRdx(Int64 arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0xBA });
            _asm.AddRange(BitConverter.GetBytes(arg));
        }

        public void MovR8(Int64 arg)
        {
            _asm.AddRange(new byte[] { 0x49, 0xB8 });
            _asm.AddRange(BitConverter.GetBytes(arg));
        }

        public void MovR9(Int64 arg)
        {
            _asm.AddRange(new byte[] { 0x49, 0xB9 });
            _asm.AddRange(BitConverter.GetBytes(arg));
        }

        public void SubRsp(byte arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0x83, 0xEC });
            _asm.Add(arg);
        }

        public void CallRax()
        {
            _asm.AddRange(new byte[] { 0xFF, 0xD0 });
        }

        public void AddRsp(byte arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0x83, 0xC4 });
            _asm.Add(arg);
        }

        public void Push(Int32 arg)
        {
            _asm.Add((int)arg < 128 ? (byte)0x6A : (byte)0x68);
            _asm.AddRange((int)arg <= 255 ? new[] { (byte)arg } : BitConverter.GetBytes((int)arg));
        }

        public void MovEax(Int32 arg)
        {
            _asm.Add(0xB8);
            _asm.AddRange(BitConverter.GetBytes(arg));
        }

        public void MovEcx(Int32 arg)
        {
            _asm.Add(0xB9); // B8 (mov immediate) + 001b (ecx register offset)
            _asm.AddRange(BitConverter.GetBytes(arg));
        }

        public void CallEax()
        {
            _asm.AddRange(new byte[] { 0xFF, 0xD0 });
        }

        public void AddEsp(byte arg)
        {
            _asm.AddRange(new byte[] { 0x83, 0xC4 });
            _asm.Add(arg);
        }

        public void SubEsp(int value)
        {
            _asm.AddRange(new byte[] { (byte)(value <= 256 ? 0x83 : 0x81), 0xEC });
            _asm.AddRange(value <= 256 ? new[] { (byte)value } : BitConverter.GetBytes(value));
        }

        public void Return()
        {
            _asm.Add(0xC3);
        }

        /// <summary>
        /// Assembles a x64 function call.
        /// </summary>
        /// <param name="address">The address of the function</param>
        /// <param name="callingConvention">The calling convention of the function</param>
        /// <param name="arguments">The arguments to pass</param>
        public void FunctionCall(Int64 address, params Int64[] arguments)
        {
            // Move function address into rax
            MovRax(address);
            if (arguments.Length != 0)
            {
                // Allocate "shadow" stack space
                SubRsp((byte)(arguments.Length * 0x8));
            }
           
            // Add arguments
            for (int i = 0; i < arguments.Length; i++)
            {
                switch (i)
                {
                    case 0:
                        MovRcx(arguments[i]);
                        break;

                    case 1:
                        MovRdx(arguments[i]);
                        break;

                    case 2:
                        MovR8(arguments[i]);
                        break;

                    case 3:
                        MovR9(arguments[i]);
                        break;
                    // TODO: Add support for stack parameters
                    default:
                        throw new NotSupportedException("More than 4 arguments are not currently supported for fastcall.");
                }
            }

            // Call function
            CallRax();

            if (arguments.Length != 0)
            {
                // Deallocate shadow stack space
                AddRsp((byte) (arguments.Length * 0x8));
            }
        }

        /// <summary>
        /// Assembles a x86 function call.
        /// </summary>
        /// <param name="address">The address of the function</param>
        /// <param name="callingConvention">The calling convention of the function</param>
        /// <param name="arguments">The arguments to pass</param>
        public void FunctionCall(Int32 address, CallingConvention callingConvention, params Int32[] arguments)
        {
            // Needs to have a this pointer for ThisCall
            if (callingConvention == CallingConvention.ThisCall && arguments.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(arguments), "ThisCall calling convention needs at least one argument.");
            }

            // Move function address into eax
            MovEax(address);

            // Keep track of how many values we pushed (cleanup)
            int valuesPushed = 0;
            // Add arguments
            for (int i = arguments.Length - 1; i >= 0; i--)
            {
                // Move first parameter into ecx in thiscall
                if (callingConvention == CallingConvention.ThisCall && i == 0)
                {
                    MovEcx(arguments[i]);
                    continue;
                }
                // Push argument on the stack
                Push(arguments[i]);
                valuesPushed++;
            }

            // Call function
            CallEax();

            // Stack cleanup for stdcall or winapi
            if ((callingConvention == CallingConvention.StdCall || callingConvention == CallingConvention.Winapi) && valuesPushed > 0)
            {
                // Remove pushed values (number of values * 4)
                AddEsp((byte)(valuesPushed * 4));
            }
        }

        /// <summary>
        /// Assembles a function call.
        /// </summary>
        /// <param name="address">The address of the function</param>
        /// <param name="callingConvention">The calling convention of the function</param>
        /// <param name="arguments">The arguments to pass</param>
        public void FunctionCall(IntPtr address, CallingConvention callingConvention, params IntPtr[] arguments)
        {
            if (_is64Bit) // 64-bit
            {
                Int64[] args = new Int64[arguments.Length];
                for (var i = 0; i < arguments.Length; i++)
                {
                    args[i] = (Int64)arguments[i];
                }
                FunctionCall((Int64)address, args);
            }
            else // 32-bit
            {
                Int32[] args = new Int32[arguments.Length];
                for (var i = 0; i < arguments.Length; i++)
                {
                    args[i] = (Int32)arguments[i];
                }
                FunctionCall((Int32)address, callingConvention, args);
            }
        }

        public byte[] ToByteArray() => _asm.ToArray();
    }
}