using System;
using System.Diagnostics;
using Test.Tests;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;

// look into..
// http://aleph.sagemath.org/?z=eJzLyU9M0VDKKCkpKLbS10_KLEkqTc5OLdHLL0rXz03MSdLPKU_VTU_NSy1KLMkv0i9KLNcvySwAieoVVCpp8nIBWQq2CkGp6allGnm2xgZAoYKizLwSBaAEWFZDEwD2OyF9&lang=sage
// http://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/lwe.html
// http://www.iacr.org/news/files/2013-04-29lwe-generator.pdf

namespace Test
{
    class Program
    {
        const int CYCLE_COUNT = 1000;
        const string CON_TITLE = "RLWE> ";

        #region Main
        static void Main(string[] args)
        {
            ConsoleUtils.SizeConsole(80, 60);
            ConsoleUtils.CenterConsole();
            Console.Title = "RLWE Sharp Test Suite";

            // header
            Console.WriteLine("**********************************************");
            Console.WriteLine("* Ring-LWE Encrypt in C# (RLWE Sharp)        *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.1                            *");
            Console.WriteLine("* Date:      June 8, 2015                    *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");
            Console.WriteLine("COMPILE as Any CPU | Release mode, RUN the .exe for real timings");
            Console.WriteLine("");

            if (Debugger.IsAttached)
            {
                Console.WriteLine("You are running in Debug mode! Compiled times will be much faster..");
                Console.WriteLine("");
            }

            Console.WriteLine(CON_TITLE + "Run Validation Tests? Press 'Y' to run, any other key to skip..");
            ConsoleKeyInfo keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                // encrypt
                Console.WriteLine("******TESTING ENCRYPTION AND DECRYPTION******");
                RunTest(new RLWEEncryptionTest());
                Console.WriteLine("");/**/

                // serialization tests
                Console.WriteLine("******TESTING KEY SERIALIZATION******");
                RunTest(new RLWEKeyTest());
                Console.WriteLine("");/**/

                Console.WriteLine("******TESTING PARAMETERS******");
                RunTest(new RLWEParamTest());
                Console.WriteLine("");/**/

                // cca2 encryption
                Console.WriteLine("******TESTING SIGNING FUNCTIONS******");
                RunTest(new RLWESignTest());
                Console.WriteLine("");/**/
            }

            Console.WriteLine("");
            Console.WriteLine(CON_TITLE + "Run Speed Tests? Press 'Y' to run, any other key to skip..");
            keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                KeyGenSpeed(CYCLE_COUNT);
                EncryptionSpeed(CYCLE_COUNT);
                DecryptionSpeed(CYCLE_COUNT);
                Console.WriteLine("Speed Tests Completed!");
                Console.WriteLine("");
            }

            Console.WriteLine("");
            Console.WriteLine(CON_TITLE + "Run Looping Full-Cycle Tests? Press 'Y' to run, all other keys close..");
            keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                Console.WriteLine("");
                Console.WriteLine("******Looping: Key Generation/Encryption/Decryption and Verify Test******");
                Console.WriteLine(string.Format("Testing {0} Full Cycles, throws on all failures..", CYCLE_COUNT));
                Console.WriteLine("");
                try
                {
                    Console.WriteLine("Test cycle using the RLWEN256Q7681 parameter set.");
                    CycleTest(CYCLE_COUNT, RLWEParamSets.RLWEN256Q7681);
                    Console.WriteLine("");
                    Console.WriteLine("Test cycle using the RLWEN512Q12289 parameter set.");
                    CycleTest(CYCLE_COUNT, RLWEParamSets.RLWEN512Q12289);
                    Console.WriteLine("");
                    Console.WriteLine(CON_TITLE + "All tests have completed, press any key to close..");
                    Console.ReadKey();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Loop test failed! " + ex.Message);
                    Console.WriteLine(CON_TITLE + "Press any key to close");
                    Console.ReadKey();
                }
            }
            else
            {
                Environment.Exit(0);
            }
        }

        static void RunTest(ITest Test)
        {
            try
            {
                Test.Progress -= OnTestProgress;
                Test.Progress += new EventHandler<TestEventArgs>(OnTestProgress);
                Console.WriteLine(Test.Description);
                Console.WriteLine(Test.Test());
                Console.WriteLine();
            }
            catch (Exception Ex)
            {
                Console.WriteLine("An error has occured!");
                Console.WriteLine(Ex.Message);
                Console.WriteLine("");
                Console.WriteLine(CON_TITLE + "Continue Testing? Press 'Y' to continue, all other keys abort..");
                ConsoleKeyInfo keyInfo = Console.ReadKey();

                if (!keyInfo.Key.Equals(ConsoleKey.Y))
                    Environment.Exit(0);
                else
                    Console.WriteLine();
            }
        }

        static void OnTestProgress(object sender, TestEventArgs e)
        {
            Console.WriteLine(e.Message);
        }
        #endregion

        #region Timing Tests
        static void CycleTest(int Iterations, RLWEParameters Param)
        {
            Stopwatch runTimer = new Stopwatch();
            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                FullCycle(Param);
            runTimer.Stop();

            double elapsed = runTimer.Elapsed.TotalMilliseconds;
            Console.WriteLine(string.Format("{0} cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Average cycle time: {0} ms", elapsed / Iterations));
            Console.WriteLine("");
        }

        static void DecryptionSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("******Looping Decryption Test: Testing {0} Iterations******", Iterations));

            Console.WriteLine("Test decryption times using the RLWEN256Q7681 parameter set.");
            double elapsed = Decrypt(Iterations, RLWEParamSets.RLWEN256Q7681);
            Console.WriteLine(string.Format("{0} decryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Decryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            Console.WriteLine("Test decryption times using the RLWEN512Q12289 parameter set.");
            elapsed = Decrypt(Iterations, RLWEParamSets.RLWEN512Q12289);
            Console.WriteLine(string.Format("{0} decryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Decryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
        }

        static void EncryptionSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("******Looping Encryption Test: Testing {0} Iterations******", Iterations));
            Console.WriteLine("Test encryption times using the RLWEN256Q7681 parameter set.");
            double elapsed = Encrypt(Iterations, RLWEParamSets.RLWEN256Q7681);
            Console.WriteLine(string.Format("{0} encryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Encryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            Console.WriteLine("Test encryption times using the RLWEN512Q12289 parameter set.");
            elapsed = Encrypt(Iterations, RLWEParamSets.RLWEN512Q12289);
            Console.WriteLine(string.Format("{0} encryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Encryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
        }

        static void FullCycle(RLWEParameters Param)
        {
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(Param);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] enc;

            using (RLWEEncrypt mpe = new RLWEEncrypt(Param))
            {
                mpe.Initialize(true, akp);

                byte[] data = new byte[mpe.MaxPlainText];
                enc = mpe.Encrypt(data);
                mpe.Initialize(false, akp);
                byte[] dec = mpe.Decrypt(enc);

                if (!Compare.AreEqual(dec, data))
                    throw new Exception("Encryption test: decryption failure!");
            }
        }

        static void KeyGenSpeed(int Iterations = 1000)
        {
            Console.WriteLine(string.Format("N | Q | Sigma: Key creation average time over {0} passes:", Iterations));
            Stopwatch runTimer = new Stopwatch();

            double elapsed = KeyGenerator(Iterations, RLWEParamSets.RLWEN256Q7681);
            Console.WriteLine(string.Format("256 7681 11.31: avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Creation Rate is {0} keys per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            elapsed = KeyGenerator(Iterations, RLWEParamSets.RLWEN512Q12289);
            Console.WriteLine(string.Format("512 12289 12.18: avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Creation Rate is {0} keys per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
        }

        static double Decrypt(int Iterations, RLWEParameters Param)
        {
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(Param);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] ptext = new CSPRng().GetBytes(Param.N >> 3);
            byte[] rtext = new byte[Param.N >> 3];
            byte[] ctext;
            Stopwatch runTimer = new Stopwatch();

            using (RLWEEncrypt mpe = new RLWEEncrypt(Param))
            {
                mpe.Initialize(true, akp);
                ctext = mpe.Encrypt(ptext);
                mpe.Initialize(false, akp);

                runTimer.Start();
                for (int i = 0; i < Iterations; i++)
                    rtext = mpe.Decrypt(ctext);
                runTimer.Stop();
            }

            //if (!Compare.AreEqual(ptext, rtext))
            //    throw new Exception("Encryption test: decryption failure!");

            return runTimer.Elapsed.TotalMilliseconds;
        }

        static double Encrypt(int Iterations, RLWEParameters Param)
        {
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(Param);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] ptext = new CSPRng().GetBytes(Param.N >> 3);
            byte[] ctext;
            Stopwatch runTimer = new Stopwatch();

            using (RLWEEncrypt mpe = new RLWEEncrypt(Param))
            {
                mpe.Initialize(true, akp);

                runTimer.Start();
                for (int i = 0; i < Iterations; i++)
                    ctext = mpe.Encrypt(ptext);
                runTimer.Stop();
            }

            return runTimer.Elapsed.TotalMilliseconds;
        }

        static double KeyGenerator(int Iterations, RLWEParameters Param)
        {
            // new SP20Prng(SeedGenerators.CSPRsg, 16384, 32, 10) // salsa20
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(Param, new CTRPrng(BlockCiphers.RDX, SeedGenerators.CSPRsg, 16384, 16)); // aes128
            IAsymmetricKeyPair akp;
            Stopwatch runTimer = new Stopwatch();

            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                akp = mkgen.GenerateKeyPair();
            runTimer.Stop();

            return runTimer.Elapsed.TotalMilliseconds;
        }
        #endregion
    }
}
