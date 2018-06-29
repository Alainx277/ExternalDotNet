using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExternalDotNet
{
    public class MemoryWriteException : Exception
    {
        public IntPtr Address;

        public MemoryWriteException()
        {

        }

        public MemoryWriteException(IntPtr address)
        {
            Address = address;
        }

        public MemoryWriteException(string message) : base(message)
        {

        }

        public MemoryWriteException(string message, Exception innerException) : base(message, innerException)
        {

        }
    }
}