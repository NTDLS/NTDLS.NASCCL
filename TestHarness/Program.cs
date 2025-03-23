using NTDLS.Permafrost;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TestHarness
{
    internal class Program
    {
        static Stopwatch _stopwatch = new();
        public delegate byte[] ByteAction();

        static void Main()
        {
            TimedAutoResetMode(100);
            TimedStreamContinuousMode(100);

            using var permafrost = new PermafrostCipher("ThisIsTheP@$$w0Rd!", PermafrostMode.AutoReset);
            var cipherBytes = permafrost.EncryptString("This is some text that I would like to keep safe if that is ok with you? Oh, it is? Good!");
            var decipheredText = permafrost.DecryptString(cipherBytes);

            EncryptFile("C:\\Users\\ntdls\\Desktop\\TestInput.txt", "C:\\Users\\ntdls\\Desktop\\TestOutput.txt");
            DecryptFile("C:\\Users\\ntdls\\Desktop\\TestOutput.txt", "C:\\Users\\ntdls\\Desktop\\TestDecryptesOutput.txt");

            //EncryptAndCompressFile("C:\\Users\\ntdls\\Desktop\\TestInput.txt", "C:\\Users\\ntdls\\Desktop\\TestOutput.txt");
            //DecryptAndDecompressFile("C:\\Users\\ntdls\\Desktop\\TestOutput.txt", "C:\\Users\\ntdls\\Desktop\\TestDecryptesOutput.txt");

            Console.WriteLine("Press [enter] to exit.");
            Console.ReadLine();
        }

        public static void SaveEncryptedBytesAsBitmap(byte[] data, string outputPath)
        {
            // Make the image as square as possible.
            int width = (int)Math.Ceiling(Math.Sqrt(data.Length));
            int height = (int)Math.Ceiling(data.Length / (double)width);

            using var bmp = new Bitmap(width, height, PixelFormat.Format24bppRgb);

            int dataIndex = 0;
            for (int y = 0; y < height && dataIndex < data.Length; y++)
            {
                for (int x = 0; x < width && dataIndex < data.Length; x++)
                {
                    byte value = data[dataIndex++];
                    var color = Color.FromArgb(value, value, value); // grayscale
                    bmp.SetPixel(x, y, color);
                }
            }

            bmp.Save(outputPath, ImageFormat.Png);
        }

        static byte[] TimeInTicks(ByteAction method, out double elapsedTicks)
        {
            _stopwatch.Restart();
            var result = method();
            elapsedTicks = _stopwatch.ElapsedTicks;
            return result;
        }

        public delegate string StringAction();
        static string TimeInTicks(StringAction method, out double elapsedTicks)
        {
            _stopwatch.Restart();
            var result = method();
            elapsedTicks = _stopwatch.ElapsedTicks;
            return result;
        }

        static void TimedAutoResetMode(int iterations)
        {
            double elapsedTicks = 0;
            using var permafrost = new PermafrostCipher("This is my somewhat Long Pa$$word! OK!?", NTDLS.Permafrost.PermafrostMode.AutoReset);
            string originalText = "This is some text that I would like to keep safe if that is ok with you? Oh, it is? Good!";

            for (int i = 0; i < iterations; i++)
            {
                var cipherBytes = TimeInTicks(()
                    => permafrost.EncryptString(originalText), out var time);
                elapsedTicks += time;

                var decipheredText = TimeInTicks(()
                    => permafrost.DecryptString(cipherBytes), out time);
                elapsedTicks += time;

                if (decipheredText != originalText)
                {
                    throw new Exception("Decryption failed.");
                }
            }

            Console.WriteLine($"Elapsed time: {(elapsedTicks / ((double)Stopwatch.Frequency)):n2}");
        }

        static void TimedStreamContinuousMode(int iterations)
        {
            double elapsedTicks = 0;

            var cipherBytesList = new List<byte[]>();
            var random = new Random();

            var seedBytes = new byte[32];
            random.NextBytes(seedBytes);

            using var permafrost = new PermafrostCipher("This is my somewhat Long Pa$$word! OK!?", NTDLS.Permafrost.PermafrostMode.Continuous, seedBytes, random.Next(64, 2048));

            //Encrypt a bunch of random strings and store the cipher bytes
            byte[]? originalHash;
            using (var sha256 = SHA256.Create())
            {
                for (int i = 0; i < iterations; i++)
                {
                    var plainText = RandomStringGenerator.Generate(random.Next(128, 2048));
                    var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

                    sha256.TransformBlock(plainTextBytes, 0, plainText.Length, null, 0);

                    var cipherBytes = TimeInTicks(()
                        => permafrost.Cipher(plainTextBytes), out var time);
                    elapsedTicks += time;

                    cipherBytesList.Add(cipherBytes);
                }

                sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                originalHash = sha256.Hash;
            }

            //Reset the stream and decrypt the cipher bytes.
            permafrost.ResetStream();

            //Decrypt the cipher bytes and hash the result
            byte[]? decipherHash;
            using (var sha256 = SHA256.Create())
            {
                foreach (var cipherBytes in cipherBytesList)
                {
                    var plainTextBytes = TimeInTicks(()
                        => permafrost.Cipher(cipherBytes), out var time);

                    sha256.TransformBlock(plainTextBytes, 0, cipherBytes.Length, null, 0);
                }

                sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                decipherHash = sha256.Hash;
            }

            if (originalHash == null || decipherHash?.SequenceEqual(originalHash) != true)
            {
                throw new Exception("Decryption failed.");
            }

            Console.WriteLine($"Original Hash: {Convert.ToHexStringLower(originalHash)}");
            Console.WriteLine($"Decipher Hash: {Convert.ToHexStringLower(decipherHash)}");

            Console.WriteLine($"Elapsed time: {(elapsedTicks / ((double)Stopwatch.Frequency)):n2}");
        }

        public static void EncryptAndCompressFile(string inputPath, string outputPath)
        {
            byte[] buffer = new byte[8192];

            using var input = File.OpenRead(inputPath);
            using var output = File.Create(outputPath);
            using var permafrost = new PermafrostStream(output, "ThisIsTheP@$$w0Rd!");
            using var gzip = new GZipStream(permafrost, CompressionLevel.SmallestSize);

            int bytesRead;
            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                gzip.Write(buffer, 0, bytesRead);
            }
        }

        public static void DecryptAndDecompressFile(string inputPath, string outputPath)
        {
            byte[] buffer = new byte[8192];

            using var input = File.OpenRead(inputPath);
            using var permafrost = new PermafrostStream(input, "ThisIsTheP@$$w0Rd!");
            using var gzip = new GZipStream(permafrost, CompressionMode.Decompress);
            using var output = File.Create(outputPath);

            int bytesRead;
            while ((bytesRead = gzip.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, bytesRead);
            }
        }

        public static void EncryptFile(string inputPath, string outputPath)
        {
            byte[] buffer = new byte[8192];

            using var input = File.OpenRead(inputPath);
            using var output = File.Create(outputPath);
            using var permafrost = new PermafrostStream(output, "ThisIsTheP@$$w0Rd!");

            int bytesRead;
            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                permafrost.Write(buffer, 0, bytesRead);
            }

            //input.Close();
            //output.Close();

            //var bytes = File.ReadAllBytes(inputPath);
            //SaveEncryptedBytesAsBitmap(bytes, outputPath + ".png");
        }

        public static void DecryptFile(string inputPath, string outputPath)
        {
            byte[] buffer = new byte[8192];

            using var input = File.OpenRead(inputPath);
            using var permafrost = new PermafrostStream(input, "ThisIsTheP@$$w0Rd!");
            using var output = File.Create(outputPath);

            int bytesRead;
            while ((bytesRead = permafrost.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, bytesRead);
            }
        }
    }
}
