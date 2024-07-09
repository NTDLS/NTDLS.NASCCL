using NTDLS.NASCCL;
using System;
using System.Text;

namespace TestHarness
{
    internal class Program
    {
        static void TimedTest(int iterations)
        {
            var cryptoStream = new CryptoStream("This is my somewhat Long Pa$$word! OK!?");

            var startTime = DateTime.UtcNow;

            string originalText = "This is some text that I would like to keep safe if that is ok with you? Oh, it is? Good!";

            for (int i = 0; i < iterations; i++)
            {
                var cipherBytes = cryptoStream.Cipher(originalText);
                var decipherBytes = cryptoStream.Cipher(cipherBytes);
                string decipheredText = Encoding.UTF8.GetString(decipherBytes);

                if (decipheredText != originalText)
                {
                    throw new Exception("Decryption failed.");
                }
            }

            Console.WriteLine($"Elapsed time: {(DateTime.UtcNow - startTime).TotalMilliseconds:n0}");
        }

        static void Main()
        {
            TimedTest(10000);

            var cryptoStream = new CryptoStream("ThisIsTheP@$$w0Rd!");
            var cipherBytes = cryptoStream.Cipher("This is some text that I would like to keep safe if that is ok with you? Oh, it is? Good!");
            var decipherBytes = cryptoStream.Cipher(cipherBytes);
            string decipheredText = Encoding.UTF8.GetString(decipherBytes);

            Console.WriteLine("Press [enter] to exit.");
            Console.ReadLine();
        }
    }
}
