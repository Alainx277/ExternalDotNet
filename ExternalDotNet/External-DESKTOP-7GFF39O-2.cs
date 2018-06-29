using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ExternalDotNet
{
    public class External
    {
        public Process AssociatedProcess
        {
            get { return _associatedProcess; }
        }

        public bool Is64Bit
        {
            get { return _handle == IntPtr.Zero ? throw new InvalidOperationException("The process needs to be opened first.") : _is64Bit; }
        }

        private Process _associatedProcess;
        private IntPtr _handle = IntPtr.Zero;
        private bool _is64Bit;

        /// <param name="pid">The process id</param>
        public External(int pid)
        {
            _associatedProcess = Process.GetProcessById(pid);
        }

        /// <param name="name">The process name</param>
        public External(string name)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name), "Process name can't be null.");
            }

            Process[] processes = Process.GetProcessesByName(name);
            if (processes.Length == 0)
            {
                throw new ArgumentException("Process with specified name doesn't exist.");
            }

            _associatedProcess = processes.First();
        }

        /// <param name="process">The process</param>
        public External(Process process)
        {
            _associatedProcess = process;
        }

        /// <summary>
        /// Opens a process handle
        /// </summary>
        /// <param name="accessFlags">The access permissions for the handle</param>
        /// <exception cref="ProcessOpenException">Thrown if openprocess fails</exception>
        public void OpenProcess(Native.ProcessAccessFlags accessFlags)
        {
            _handle = Native.OpenProcess(accessFlags, false, AssociatedProcess.Id);
            if (_handle == IntPtr.Zero)
            {
                throw new ProcessOpenException();
            }

            // Process is always 32bit on 32bit os
            if (!Environment.Is64BitOperatingSystem)
            {
                _is64Bit = false;
                return;
            }

            // Check for wow64 process
            Native.IsWow64Process(_handle, out bool is32Bit);
            _is64Bit = !is32Bit;
        }

        /// <summary>
        /// Reads a structure from memory
        /// </summary>
        /// <typeparam name="T">The struct type to read (must be sequential)</typeparam>
        /// <param name="address">The address to read at</param>
        /// <returns>A structure of type T</returns>
        public T Read<T>(IntPtr address) where T : struct
        {
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Can't read without valid handle.");
            }

            // Get type size
            int typeSize = Marshal.SizeOf(typeof(T));
            // Allocate buffer
            byte[] readBytes = new byte[typeSize];

            // Read memory
            if (!Native.ReadProcessMemory(_handle, address, readBytes, readBytes.Length, out IntPtr _))
            {
                throw new MemoryReadException($"Can't read at address {address}");
            }

            // Allocate struct pointer
            IntPtr structurePtr = Marshal.AllocHGlobal(typeSize);
            // Copy byte array
            Marshal.Copy(readBytes, 0, structurePtr, typeSize);
            // Convert to struct
            T readObject = Marshal.PtrToStructure<T>(structurePtr);
            // Free pointer
            Marshal.FreeHGlobal(structurePtr);

            return readObject;
        }

        /// <summary>
        /// Writes a byte array
        /// </summary>
        /// <param name="address">The address to read at</param>
        /// <param name="bytes">The bytes to write</param>
        /// <exception cref="MemoryWriteException">Thrown if memory write fails</exception>
        public void WriteBytes(IntPtr address, byte[] bytes)
        {
            // Write memory
            if (!Native.WriteProcessMemory(_handle, address, bytes, bytes.Length, out IntPtr _))
            {
                throw new MemoryWriteException($"Can't write at address {address}");
            }
        }

        /// <summary>
        /// Reads a byte array
        /// </summary>
        /// <param name="address">The address to read at</param>
        /// <param name="size">The number of bytes to read</param>
        /// <returns>The byte array</returns>
        /// <exception cref="MemoryReadException">Thrown if memory read fails</exception>
        public byte[] ReadBytes(IntPtr address, int size)
        {
            // Allocate buffer
            byte[] readBytes = new byte[size];

            // Read memory
            if (!Native.ReadProcessMemory(_handle, address, readBytes, readBytes.Length, out IntPtr _))
            {
                throw new MemoryReadException($"Can't read at address {address}");
            }

            // Return bytes
            return readBytes;
        }

        /// <summary>
        /// Reads a short
        /// </summary>
        /// <param name="address">The address to read at</param>
        /// <returns>The short</returns>
        /// <exception cref="MemoryReadException">Thrown if memory read fails</exception>
        public short ReadShort(IntPtr address)
        {
            return BitConverter.ToInt16(ReadBytes(address, 2), 0);
        }

        /// <summary>
        /// Reads a 32bit int
        /// </summary>
        /// <param name="address">The address to read at</param>
        /// <returns>The 32bit int</returns>
        /// <exception cref="MemoryReadException">Thrown if memory read fails</exception>
        public Int32 ReadInt32(IntPtr address)
        {
            return BitConverter.ToInt32(ReadBytes(address, 4), 0);
        }

        /// <summary>
        /// Reads a 64bit int
        /// </summary>
        /// <param name="address">The address to read at</param>
        /// <returns>The 64bit int</returns>
        /// <exception cref="MemoryReadException">Thrown if memory read fails</exception>
        public Int64 ReadInt64(IntPtr address)
        {
            return BitConverter.ToInt64(ReadBytes(address, 8), 0);
        }

        /// <summary>
        /// Reads a string
        /// </summary>
        /// <param name="address">The address to read at</param>
        /// <param name="encoding">The string encoding to use</param>
        /// <param name="maxLength">The max length of the string</param>
        /// <returns>The string</returns>
        /// <exception cref="MemoryReadException">Thrown if memory read fails</exception>
        public string ReadString(IntPtr address, Encoding encoding, int maxLength = Int32.MaxValue)
        {
            List<byte> bytes = new List<byte>();

            for (int i = 0; i < maxLength; i++)
            {
                byte read = ReadBytes(address + bytes.Count, 1)[0];

                if (read != 0x00)
                    bytes.Add(read);
                else break;
            }

            return encoding.GetString(bytes.ToArray());
        }

        /// <summary>
        /// Allocates memory in remote process
        /// </summary>
        /// <param name="lpAddress">The address to allocate at (IntPtr.Zero for any)</param>
        /// <param name="dwSize">The size of memory to allocate</param>
        /// <param name="flAllocationType">The allocation type</param>
        /// <param name="flProtect">The memory protection</param>
        /// <returns>The address of allocated memory (IntPtr.Zero on fail)</returns>
        /// <exception cref="MemoryAllocationException">Thrown if memory can't be allocated</exception>
        public IntPtr Allocate(IntPtr lpAddress, uint dwSize, Native.AllocationType flAllocationType = Native.AllocationType.Commit | Native.AllocationType.Reserve, Native.MemoryProtection flProtect = Native.MemoryProtection.ExecuteReadWrite)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Requires open handle.");
            }

            IntPtr allocation = Native.VirtualAllocEx(_handle, lpAddress, dwSize, flAllocationType, flProtect);

            if (allocation == IntPtr.Zero)
            {
                throw new MemoryAllocationException();
            }

            return allocation;
        }

        /// <summary>
        /// Allocates memory in remote process
        /// </summary>
        /// <param name="dwSize">The size of memory to allocate</param>
        /// <returns>A pointer to the allocated memory</returns>
        public IntPtr Allocate(uint dwSize)
        {
            return Allocate(IntPtr.Zero, dwSize);
        }

        /// <summary>
        /// Allocates memory and writes to it in remote process
        /// </summary>
        /// <param name="dwSize">The size of memory to allocate</param>
        /// <param name="bytes">The bytes to write</param>
        /// <returns>A pointer to the allocated memory</returns>
        public IntPtr AllocateAndWrite(byte[] bytes)
        {
            IntPtr allocated = Allocate(IntPtr.Zero, (uint)bytes.Length);
            WriteBytes(allocated, bytes);
            return allocated;
        }

        /// <summary>
        /// Checks if the associated process contains a certain module
        /// </summary>
        /// <param name="moduleName">THe name of the module</param>
        /// <returns>If the associated process contains the module</returns>
        public bool HasModule(string moduleName)
        {
            foreach (ProcessModule processModule in _associatedProcess.Modules)
            {
                try
                {
                    if (processModule.ModuleName.ToLower() == moduleName.ToLower())
                    {
                        return true;
                    }
                }
                catch (Exception)
                {
                    // ignored
                }
            }

            return false;
        }

        /// <summary>
        /// Checks if the associated process contains a certain module
        /// </summary>
        /// <param name="moduleName">THe regex of the module</param>
        /// <returns>If the associated process contains the module</returns>
        public bool HasModule(Regex moduleName)
        {
            foreach (ProcessModule processModule in _associatedProcess.Modules)
            {
                try
                {
                    if (moduleName.IsMatch(processModule.ModuleName))
                    {
                        return true;
                    }
                }
                catch (Exception)
                {
                    // ignored
                }
            }

            return false;
        }

        /// <summary>
        /// Get all module names
        /// </summary>
        /// <returns>A list of module names</returns>
        public List<string> GetModuleNames()
        {
            List<string> modules = new List<string>();

            foreach (ProcessModule processModule in _associatedProcess.Modules)
            {
                try
                {
                    modules.Add(processModule.ModuleName);
                }
                catch (Exception)
                {
                    // ignored
                }
            }

            return modules;
        }

        /// <summary>
        /// Gets all exports for a module
        /// </summary>
        /// <param name="moduleName">The module name</param>
        /// <param name="useRegex">If the module name should use regex</param>
        /// <returns>A dictonary containing the exports</returns>
        /// <exception cref="ThreadCreationException">Thrown if thread creation failed</exception>
        public Dictionary<string, IntPtr> GetModuleExports(string moduleName, bool useRegex = false)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Requires open handle.");
            }

            IntPtr mod = IntPtr.Zero;
            Dictionary<string, IntPtr> exportDictionary = new Dictionary<string, IntPtr>();

            foreach (ProcessModule module in _associatedProcess.Modules)
            {
                // Check module name
                if ((useRegex && Regex.IsMatch(module.ModuleName, moduleName)) || (!useRegex && module.ModuleName.ToLower().Contains(moduleName.ToLower())))
                {
                    // Get base address
                    mod = module.BaseAddress;
                    break;
                }
            }

            // Check for invalid module base
            if (mod == IntPtr.Zero)
            {
                throw new ArgumentException($"No module containing {moduleName} exists.", nameof(moduleName));
            }

            // TODO: wtf is this peb shit

            IntPtr exports = mod + ReadInt32(mod + ReadInt32(mod + 0x3C) + (Is64Bit ? 0x88 : 0x78));

            int count = ReadInt32(exports + 0x18);

            IntPtr names = mod + ReadInt32(exports + 0x20);

            IntPtr ordinals = mod + ReadInt32(exports + 0x24);

            IntPtr relatives = mod + ReadInt32(exports + 0x1C);

            for (int i = 0; i < count; i++)
            {
                string name = ReadString(mod + ReadInt32(names + i * 4), Encoding.ASCII, 32);
                short ordinal = ReadShort(ordinals + i * 2);

                IntPtr address = mod + ReadInt32(relatives + ordinal * 4);

                exportDictionary[name] = address;
            }

            return exportDictionary;
        }

        /// <summary>
        /// Creates a thread in the remote process
        /// </summary>
        /// <param name="address">The thread start address</param>
        /// <returns>A handle to the thread</returns>
        /// <exception cref="ThreadCreationException">Thrown if thread could not be created</exception>
        public IntPtr CreateThread(IntPtr address)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Requires open handle.");
            }

            // Create thread
            IntPtr handle = Native.CreateRemoteThread(_handle, IntPtr.Zero, 0, address, IntPtr.Zero, 0, out IntPtr _);

            // Check for fail
            if (handle == IntPtr.Zero)
            {
                throw new ThreadCreationException();
            }

            return handle;
        }

        /// <summary>
        /// Makes sure a handle is closed
        /// </summary>
        /// <param name="handle">The handle to close</param>
        public static void HandleEnsureClosed(ref IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                Native.CloseHandle(handle);
                handle = IntPtr.Zero;
            }
        }

        /// <summary>
        /// Executes the specified bytecode in the remote process
        /// </summary>
        /// <param name="bytecode">The bytecode to run</param>
        /// <exception cref="InvalidOperationException">Thrown if there is no process handle</exception>
        /// <exception cref="ThreadCreationException">Thrown if thread could not be created</exception>
        /// <exception cref="MemoryAllocationException">Thrown if memory can't be allocated</exception>
        /// <exception cref="MemoryWriteException">Thrown if memory write fails</exception>
        /// <returns>The thread handle</returns>
        public IntPtr Execute(byte[] bytecode)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Requires open handle.");
            }

            // Allocate memory
            IntPtr allocated = Allocate(IntPtr.Zero, (uint)bytecode.Length);
            // Write bytecode
            WriteBytes(allocated, bytecode);
            // Execute
            return CreateThread(allocated);
        }

        /// <summary>
        /// Executes the specified bytecode in the remote process
        /// </summary>
        /// <param name="bytecode">The bytecode to run</param>
        /// <param name="allocatedPtr">[Out] A pointer to the allocated memory</param>
        /// <exception cref="InvalidOperationException">Thrown if there is no process handle</exception>
        /// <exception cref="ThreadCreationException">Thrown if thread could not be created</exception>
        /// <exception cref="MemoryAllocationException">Thrown if memory can't be allocated</exception>
        /// <exception cref="MemoryWriteException">Thrown if memory write fails</exception>
        /// <returns>The thread handle</returns>
        public IntPtr Execute(byte[] bytecode, out IntPtr allocatedPtr)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Requires open handle.");
            }

            // Allocate memory
            allocatedPtr = Allocate(IntPtr.Zero, (uint)bytecode.Length);
            // Write bytecode
            WriteBytes(allocatedPtr, bytecode);
            // Execute
            return CreateThread(allocatedPtr);
        }

        /// <summary>
        /// Executes the specified assembler in the remote process
        /// </summary>
        /// <param name="assembler">The assembler to run</param>
        /// <exception cref="InvalidOperationException">Thrown if there is no process handle</exception>
        /// <exception cref="ThreadCreationException">Thrown if thread could not be created</exception>
        /// <exception cref="MemoryAllocationException">Thrown if memory can't be allocated</exception>
        /// <exception cref="MemoryWriteException">Thrown if memory write fails</exception>
        /// /// <returns>The thread handle</returns>
        public IntPtr Execute(Assembler assembler)
        {
            return Execute(assembler.ToByteArray());
        }

        /// <summary>
        /// Executes the specified bytecode in the remote process and waits for exit
        /// </summary>
        /// <param name="bytecode">The bytecode to run</param>
        /// <param name="cleanup">If the memory should be cleaned up</param>
        /// <returns>The thread exit code</returns>
        /// <exception cref="InvalidOperationException">Thrown if there is no process handle</exception>
        /// <exception cref="ThreadCreationException">Thrown if thread could not be created</exception>
        /// <exception cref="MemoryAllocationException">Thrown if memory can't be allocated</exception>
        /// <exception cref="MemoryWriteException">Thrown if memory write fails</exception>
        /// <exception cref="ThreadExitCodeException">Thrown if GetExitCodeThread fails</exception>
        public async Task<IntPtr> ExecuteAndWait(byte[] bytecode, bool cleanup = true)
        {
            IntPtr allocatedMemory = IntPtr.Zero;
            // Execute bytecode
            IntPtr threadHandle = Execute(bytecode, out allocatedMemory);
            // Create task and wait for thread exit
            await Task.Run(() => Native.WaitForSingleObject(threadHandle, -1));
            // Get exit code
            if (!Native.GetExitCodeThread(threadHandle, out IntPtr exitCode))
            {
                throw new ThreadExitCodeException();
            }

            // Cleanup allocated memory if requested
            if (cleanup)
            {
                Native.VirtualFreeEx(_handle, allocatedMemory, bytecode.Length,
                    Native.AllocationType.Decommit | Native.AllocationType.Release);
            }

            return exitCode;
        }

        /// <summary>
        /// Executes the specified assembler in the remote process and waits for exit
        /// </summary>
        /// <param name="assembler">The assembler to run</param>
        /// <param name="cleanup">If the memory should be cleaned up</param>
        /// <returns>The thread exit code</returns>
        /// <exception cref="InvalidOperationException">Thrown if there is no process handle</exception>
        /// <exception cref="ThreadCreationException">Thrown if thread could not be created</exception>
        /// <exception cref="MemoryAllocationException">Thrown if memory can't be allocated</exception>
        /// <exception cref="MemoryWriteException">Thrown if memory write fails</exception>
        /// <exception cref="ThreadExitCodeException">Thrown if GetExitCodeThread fails</exception>
        public async Task<IntPtr> ExecuteAndWait(Assembler assembler, bool cleanup = true)
        {
            return await ExecuteAndWait(assembler.ToByteArray(), cleanup);
        }

        /// <summary>
        /// Calls the specified function in the remote process
        /// </summary>
        /// <param name="address">The address to call</param>
        /// <param name="callingConvention">The calling convention to use</param>
        /// <param name="arguments">The arguments to pass</param>
        /// <returns>The thread exit code</returns>
        /// <exception cref="InvalidOperationException">Thrown if there is no process handle</exception>
        /// <exception cref="ThreadCreationException">Thrown if thread could not be created</exception>
        /// <exception cref="MemoryAllocationException">Thrown if memory can't be allocated</exception>
        /// <exception cref="MemoryWriteException">Thrown if memory write fails</exception>
        /// <exception cref="ThreadExitCodeException">Thrown if GetExitCodeThread fails</exception>
        public async Task<IntPtr> ExecuteAndWait(Int32 address, CallingConvention callingConvention, params IntPtr[] arguments)
        {
            Assembler assembler = new Assembler();
            assembler.FunctionCall(address, callingConvention, arguments.ToInt32());
            assembler.Return();

            return await ExecuteAndWait(assembler);
        }

        /// <summary>
        /// Calls the specified function in the remote process
        /// </summary>
        /// <param name="address">The address to call</param>
        /// <param name="callingConvention">The calling convention to use</param>
        /// <param name="arguments">The arguments to pass</param>
        /// <returns>The thread exit code</returns>
        /// <exception cref="InvalidOperationException">Thrown if there is no process handle</exception>
        /// <exception cref="ThreadCreationException">Thrown if thread could not be created</exception>
        /// <exception cref="MemoryAllocationException">Thrown if memory can't be allocated</exception>
        /// <exception cref="MemoryWriteException">Thrown if memory write fails</exception>
        /// <exception cref="ThreadExitCodeException">Thrown if GetExitCodeThread fails</exception>
        public async Task<IntPtr> ExecuteAndWait(Int64 address, CallingConvention callingConvention, params IntPtr[] arguments)
        {
            Assembler assembler = new Assembler();
            assembler.FunctionCall(address, callingConvention, arguments.ToInt64());
            assembler.Return();

            return await ExecuteAndWait(assembler);
        }

        /// <summary>
        /// Calls the specified function in the remote process
        /// </summary>
        /// <param name="address">The address to call</param>
        /// <param name="callingConvention">The calling convention to use</param>
        /// <param name="arguments">The arguments to pass</param>
        /// <returns>The thread exit code</returns>
        /// <exception cref="InvalidOperationException">Thrown if there is no process handle</exception>
        /// <exception cref="ThreadCreationException">Thrown if thread could not be created</exception>
        /// <exception cref="MemoryAllocationException">Thrown if memory can't be allocated</exception>
        /// <exception cref="MemoryWriteException">Thrown if memory write fails</exception>
        /// <exception cref="ThreadExitCodeException">Thrown if GetExitCodeThread fails</exception>
        public async Task<IntPtr> ExecuteAndWait(IntPtr address, CallingConvention callingConvention, params IntPtr[] arguments)
        {
            if (Is64Bit) // 64 bit
            {
                return await ExecuteAndWait(address.ToInt64(), callingConvention, arguments);
            }
            else // 32 bit
            {
                return await ExecuteAndWait(address.ToInt32(), callingConvention, arguments);
            }
        }
    }
}