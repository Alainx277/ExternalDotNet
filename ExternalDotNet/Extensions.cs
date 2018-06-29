using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExternalDotNet
{
    static class Extensions
    {
        public static Int32[] ToInt32(this IntPtr[] ptrArray)
        {
            Int32[] array = new Int32[ptrArray.Length];
            for (var i = 0; i < ptrArray.Length; i++)
            {
                array[i] = ptrArray[i].ToInt32();
            }

            return array;
        }

        public static Int64[] ToInt64(this IntPtr[] ptrArray)
        {
            Int64[] array = new Int64[ptrArray.Length];
            for (var i = 0; i < ptrArray.Length; i++)
            {
                array[i] = ptrArray[i].ToInt64();
            }

            return array;
        }
    }
}
