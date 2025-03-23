using System;
using System.Runtime.CompilerServices;

namespace NTDLS.Permafrost
{
    internal static class Extensions
    {
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void Sanitize(this byte[,] array)
        {
            int rows = array.GetLength(0);
            int columns = array.GetLength(1);

            for (int row = 0; row < rows; row++)
            {
                for (int col = 0; col < columns; col++)
                {
                    array[row, col] = 0;
                }
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void Sanitize(this byte[] array)
        {
            for (var index = 0; index < array.Length; index++)
            {
                array[index] = 0;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] Copy(this byte[] array)
        {
            var clone = new byte[array.Length];
            Buffer.BlockCopy(array, 0, clone, 0, array.Length);
            return clone;
        }

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
