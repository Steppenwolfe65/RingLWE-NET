using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE;

namespace RLWEOriginal
{
    class Program
    {
        static void Main(string[] args)
        {
            new TestRLWE().Test();
            Console.WriteLine("Test completed! Press any key to close..");
            Console.ReadKey();
        }
    }
}
