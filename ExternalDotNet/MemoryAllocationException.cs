using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExternalDotNet
{
    public class MemoryAllocationException : Exception
    {
        public MemoryAllocationException()
        {

        }

        public MemoryAllocationException(string message) : base(message)
        {

        }

        public MemoryAllocationException(string message, Exception innerException) : base(message, innerException)
        {

        }
    }
}