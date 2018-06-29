using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ExternalDotNet
{
    public class External
    {
        public Process AssociatedProcess
        {
            get { return _associatedProcess; }
            set { _associatedProcess = value; }
        }

        private Process _associatedProcess;
        private IntPtr _handle = IntPtr.Zero;

        public External(int pid)
        {
            AssociatedProcess = Process.GetProcessById(pid);
        }

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

            AssociatedProcess = processes.First();
        }

        /// <summary>
        /// Opens a process handle
        /// </summary>
        /// <param name="accessFlags">The access permissions for the handle</param>
        public void OpenProcess(Native.ProcessAccessFlags accessFlags)
        {
             _handle = Native.OpenProcess(accessFlags, false, AssociatedProcess.Id);
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

            if (address == IntPtr.Zero)
            {
                throw new ArgumentNullException(nameof(address), "Address can't be 0.");
            }

            // Get type size
            int typeSize = Marshal.SizeOf(typeof(T));
            // Allocate buffer
            byte[] readBytes = new byte[typeSize];
            IntPtr lpNumberOfBytesRead = IntPtr.Zero;

            // Read memory
            if (!Native.ReadProcessMemory(_handle, address, readBytes, readBytes.Length, out lpNumberOfBytesRead))
            {
                throw new ArgumentException($"Can't read at address {address}", nameof(address));
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
    }
}
