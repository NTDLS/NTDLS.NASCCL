using System;
using System.Runtime.CompilerServices;

namespace NTDLS.NASCCL
{
    internal static class Extensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Sanitize(this byte[,] array)
        {
            for (int box = 0; box < KeyExpansion.BoxCount; box++)
            {
                for (int val = 0; val < KeyExpansion.ValueCount; val++)
                {
                    array[box, val] = 0;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Sanitize(this byte[] array)
        {
            for (int index = 0; index < array.Length; index++)
            {
                array[index] = 0;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] Copy(this byte[] array)
            => (byte[])array.Clone();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[,] Copy(this byte[,] array)
        {
            int rows = array.GetLength(0);
            int columns = array.GetLength(1);

            var clone = new byte[rows, columns];
            Buffer.BlockCopy(array, 0, clone, 0, array.Length * sizeof(byte));

            return clone;
        }
    }
}
