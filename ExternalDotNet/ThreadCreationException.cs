using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExternalDotNet
{
    public class ThreadCreationException : Exception
    {
        public ThreadCreationException()
        {

        }

        public ThreadCreationException(string message) : base(message)
        {

        }
    }
}