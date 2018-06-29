﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExternalDotNet
{
    public class ProcessOpenException : Exception
    {
        public ProcessOpenException()
        {

        }

        public ProcessOpenException(string message) : base(message)
        {

        }

        public ProcessOpenException(string message, Exception innerException) : base(message, innerException)
        {

        }
    }
}