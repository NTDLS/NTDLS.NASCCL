using System;

namespace NTDLS.NASCCL
{
    internal static class Extensions
    {
        public static void ZeroOut(this ushort[,] array)
        {
            for (int box = 0; box < HardcodedSaltValues.BoxCount; box++)
            {
                for (int val = 0; val < HardcodedSaltValues.ValueCount; val++)
                {
                    array[box, val] = 0;
                }
            }
        }

        public static void ZeroOut(this byte[] array)
        {
            for (int index = 0; index < array.Length; index++)
            {
                array[index] = 0;
            }
        }

        public static byte[] Clone(this byte[] array)
        {
            var clone = new byte[array.Length];
            Array.Copy(array, clone, array.Length);
            return clone;
        }

        public static byte[,] Clone(this byte[,] array)
        {
            int rows = array.GetLength(0);
            int columns = array.GetLength(1);

            var clone = new byte[rows, columns];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    clone[i, j] = array[i, j];
                }
            }

            return clone;
        }

        public static ushort[,] Clone(this ushort[,] array)
        {
            int rows = array.GetLength(0);
            int columns = array.GetLength(1);

            var clone = new ushort[rows, columns];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    clone[i, j] = array[i, j];
                }
            }

            return clone;
        }
    }
}
