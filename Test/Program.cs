using System;
using System.Diagnostics;
using Test.Tests;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Tools;

namespace Test
{
    class Program
    {
        const int CYCLE_COUNT = 1000;

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
            Console.WriteLine("* Release:   v1.0                            *");
            Console.WriteLine("* Date:      June 8, 2015                    *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");
            Console.WriteLine("COMPILE as Any CPU / Release mode, RUN the .exe for real timings");
            Console.WriteLine("");

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

            Console.WriteLine("Validity Tests Completed!");
            Console.WriteLine("");
            Console.WriteLine("Run Speed Tests? Press 'Y' to run, all other keys close..");
            ConsoleKeyInfo keyInfo = Console.ReadKey();

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                Console.WriteLine("");
                if (Debugger.IsAttached)
                {
                    Console.WriteLine("You are running in Debug mode! Compiled times will be much faster..");
                    Console.WriteLine("");
                }

                KeyGenSpeed(CYCLE_COUNT);
                EncryptionSpeed(CYCLE_COUNT);
                DecryptionSpeed(CYCLE_COUNT);
                Console.WriteLine("Speed Tests Completed!");
                Console.WriteLine("");
                Console.WriteLine("");
                Console.WriteLine("Run Looping Full-Cycle Tests? Press 'Y' to run, all other keys close..");
                keyInfo = Console.ReadKey();

                if (keyInfo.Key.Equals(ConsoleKey.Y))
                {
                    Console.WriteLine("");
                    Console.WriteLine("******Looping: Key Generation/Encryption/Decryption and Verify Test******");
                    Console.WriteLine(string.Format("Testing {0} Full Cycles, throws on all failures..", CYCLE_COUNT));
                    try
                    {
                        CycleTest(CYCLE_COUNT);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Loop test failed! " + ex.Message);
                        Console.WriteLine("Press any key to close");
                    }
                }

                Console.WriteLine("");
                Console.WriteLine("All tests have completed, press any key to close..");
                Console.ReadKey();
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
                Console.WriteLine("Continue Testing? Press 'Y' to continue, all other keys abort..");
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
        static void CycleTest(int Iterations)
        {
            Stopwatch runTimer = new Stopwatch();
            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                FullCycle();
            runTimer.Stop();

            double elapsed = runTimer.Elapsed.TotalMilliseconds;
            Console.WriteLine(string.Format("{0} cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Average cycle time: {0} ms", elapsed / Iterations));
            Console.WriteLine("");
        }

        static void DecryptionSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("******Looping Decryption Test: Testing {0} Iterations******", Iterations));
            Console.WriteLine("Test decryption times using the RLWEN512Q12289 parameter set.");

            double elapsed = RDecrypt(Iterations);
            Console.WriteLine(string.Format("{0} decryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine("");
        }

        static void EncryptionSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("******Looping Encryption Test: Testing {0} Iterations******", Iterations));
            Console.WriteLine("Test encryption times using the RLWEN512Q12289 parameter set.");

            double elapsed = REncrypt(Iterations);
            Console.WriteLine(string.Format("{0} encryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine("");
        }

        static void FullCycle()
        {
            RLWEParameters mpar = RLWEParamSets.RLWEN256Q7681; //RLWEN512Q12289
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] enc;

            using (RLWEEncrypt mpe = new RLWEEncrypt(mpar))
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
            Console.WriteLine(string.Format("N/Q/Sigma: Key creation average time over {0} passes:", Iterations));
            Stopwatch runTimer = new Stopwatch();

            double elapsed = N256Q7681(Iterations);
            Console.WriteLine(string.Format("256/7681/11.31: avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));

            elapsed = N512Q12289(Iterations);
            Console.WriteLine(string.Format("512/12289/12.18: avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));

            Console.WriteLine("");
        }

        static double N256Q7681(int Iterations)
        {
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(RLWEParamSets.RLWEN256Q7681);
            IAsymmetricKeyPair akp;
            Stopwatch runTimer = new Stopwatch();

            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                akp = mkgen.GenerateKeyPair();
            runTimer.Stop();

            return runTimer.Elapsed.TotalMilliseconds;
        }

        static double N512Q12289(int Iterations)
        {
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(RLWEParamSets.RLWEN512Q12289);
            IAsymmetricKeyPair akp;
            Stopwatch runTimer = new Stopwatch();

            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                akp = mkgen.GenerateKeyPair();
            runTimer.Stop();

            return runTimer.Elapsed.TotalMilliseconds;
        }

        static double RDecrypt(int Iterations)
        {
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(RLWEParamSets.RLWEN512Q12289);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] ptext = new CSPRng().GetBytes(64);
            byte[] rtext =  new byte[64];
            byte[] ctext;
            Stopwatch runTimer = new Stopwatch();

            using (RLWEEncrypt mpe = new RLWEEncrypt(RLWEParamSets.RLWEN512Q12289))
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

        static double REncrypt(int Iterations)
        {
            RLWEKeyGenerator mkgen = new RLWEKeyGenerator(RLWEParamSets.RLWEN512Q12289);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] ptext = new CSPRng().GetBytes(64);
            byte[] ctext;
            Stopwatch runTimer = new Stopwatch();

            using (RLWEEncrypt mpe = new RLWEEncrypt(RLWEParamSets.RLWEN512Q12289))
            {
                mpe.Initialize(true, akp);

                runTimer.Start();
                for (int i = 0; i < Iterations; i++)
                    ctext = mpe.Encrypt(ptext);
                runTimer.Stop();
            }

            return runTimer.Elapsed.TotalMilliseconds;
        }
        #endregion
    }
}
