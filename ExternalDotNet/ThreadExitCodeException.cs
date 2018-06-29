using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExternalDotNet
{
    public class ThreadExitCodeException : Exception
    {
        public ThreadExitCodeException()
        {

        }

        public ThreadExitCodeException(string message) : base(message)
        {

        }

        public ThreadExitCodeException(string message, Exception innerException) : base(message, innerException)
        {

        }
    }
}