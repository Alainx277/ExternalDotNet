using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExternalDotNet
{
    public class MemoryReadException : Exception
    {
        public IntPtr Address;

        public MemoryReadException()
        {

        }

        public MemoryReadException(IntPtr address)
        {
            Address = address;
        }

        public MemoryReadException(string message) : base(message)
        {

        }
    }
}