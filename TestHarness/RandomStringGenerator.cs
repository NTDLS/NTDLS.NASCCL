using System;
using System.Security.Cryptography;

namespace TestHarness
{
    public static class RandomStringGenerator
    {
        private const string DefaultCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        public static string Generate(int length, string? charset = null)
        {
            charset ??= DefaultCharset;

            if (string.IsNullOrEmpty(charset))
                throw new ArgumentException("Charset must not be empty.", nameof(charset));

            var result = new char[length];
            var charsetSpan = charset.AsSpan();
            var buffer = new byte[length];

            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(buffer);

            for (int i = 0; i < length; i++)
            {
                int index = buffer[i] % charsetSpan.Length;
                result[i] = charsetSpan[index];
            }

            return new string(result);
        }
    }
}
