using NTDLS.NASCCL;
using System;
using System.Text;

namespace TestHarness
{
    internal class Program
    {
        static void TimeUnitNegotiator()
        {
            var nasccl = new NASCCLStream("This is my somewhat Long Pa$$word! OK!?");

            DateTime startTime = DateTime.Now;

            string originalText = "This is some text that I would like to keep safe if that is ok with you? Oh, it is? Good!";

            for (int i = 0; i < 10000; i++)
            {
                var cipherBytes = nasccl.Cipher(originalText);
                var decipherBytes = nasccl.Cipher(cipherBytes);
                string decipheredText = Encoding.UTF8.GetString(decipherBytes);

                if (decipheredText != originalText)
                {
                    throw new Exception("Decryption failed.");
                }
            }

            Console.WriteLine($"Elapsed time: {(DateTime.Now - startTime).TotalMilliseconds:n0}");
        }

        static void Main(string[] args)
        {
            TimeUnitNegotiator();

            Console.ReadLine();
        }
    }
}
