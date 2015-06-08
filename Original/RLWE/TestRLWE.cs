using System;

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE
{
    /// <summary>
    /// Translation from: https://github.com/ruandc/Ring-LWE-Encryption
    /// </summary>
    public class TestRLWE
    {
        public int Test()
        {
            int i;
            int j;
            int res;
            uint[] large_m = new uint[Globals.M];
            uint[] large_a = new uint[Globals.M];
            uint[] large_p = new uint[Globals.M];
            uint[] large_r2 = new uint[Globals.M];
            uint[] large_c1 = new uint[Globals.M];
            uint[] large_c2 = new uint[Globals.M];
            uint[] large1 = new uint[Globals.M];
            uint[] large2 = new uint[Globals.M];
            uint[] largeP = new uint[Globals.M];
            uint[] a_0 = new uint[Globals.M / 2];
            uint[] a_1 = new uint[Globals.M / 2];
            Lwe RWP = new Lwe();

            res = 1;
            for (i = 0; i < 100; i++)
            {
                RWP.seed(i * i);
                RWP.knuth_yao(a_0, a_1);
                //Test knuth-yao

                RWP.seed(i * i);
                RWP.knuth_yao_smaller_tables2(large1);

                if (RWP.compare2(a_1, a_0, large1) == 0)
                {
                    res = 0;
                    Console.WriteLine("i=%d\n", i);
                    break;
                }
            }

            Console.WriteLine("knuth_yao_smaller_tables2: "); 
            if (res == 0)
                Console.WriteLine("BAD!\n");
            else
                Console.WriteLine("OK!\n");/**/


            for (i = 0; i < 100; i++)
            {
                RWP.seed(i * i);
                uint rnd = RWP.get_rand();
                uint num1 = RWP.knuth_yao_single_number(ref rnd);

                RWP.seed(i * i);
                //srand(i*i);
                rnd = RWP.get_rand();

                uint num2 = RWP.knuth_yao_smaller_tables_single_number(ref rnd);

                if (num1 != num2)
                {
                    res = 0;
                    Console.WriteLine("i=%d\n", i);
                    break;
                }
            }

            Console.WriteLine("knuth_yao_smaller_tables_single_number: "); 
            if (res == 0)
                Console.WriteLine("BAD!\n");
            else
                Console.WriteLine("OK!\n");/**/



            res = 1;
            for (i = 0; i < 100; i++)
            {
                //Test knuth-yao
                RWP.seed(i * i);
                RWP.knuth_yao(a_0, a_1);
                RWP.seed(i * i);
                RWP.knuth_yao2(large1);

                if (compare2(a_1, a_0, large1) == 0)
                    res = 0;
            }

            Console.WriteLine("knuth_yao2: "); 
            if (res == 0)
                Console.WriteLine("BAD!\n");
            else
                Console.WriteLine("OK!\n");/**/


            res = 1;
            for (i = 0; (i < 1000) && (res == 1); i++)
            {
                //Test knuth-yao
                RWP.seed(i * i);

                if (i == 0)
                {
                    RWP.a_gen2(large1);
                    for (j = 0; j < Globals.M; j++)
                        large1[j] = 1;
                }
                else
                {
                    for (j = 0; j < Globals.M; j++)
                        large1[j] = RWP.get_rand() % 16;
                }

                for (j = 0; j < Globals.M; j++)
                    large2[j] = large1[j];

                RWP.fwd_ntt2(large2);
                RWP.rearrange2(large2);
                RWP.inv_ntt2(large2);
                RWP.rearrange2(large2);


                for (j = 0; j < Globals.M; j++)
                {
                    if (large2[j] != large1[j])
                    {
                        res = 0;
                        break;
                    }
                }
            }

            Console.WriteLine("fwd/inv_ntt2: "); 
            if (res == 0)
                Console.WriteLine("BAD!\n");
            else
                Console.WriteLine("OK!\n");/**/



            res = 1;
            for (i = 0; i < 100; i++)
            {
                //Test knuth-yao
                RWP.seed(i * i);
                RWP.a_gen(a_0, a_1);
                //RWP.fwd_ntt(a_0,a_1);//

                RWP.seed(i * i);
                RWP.a_gen2(large1);
                //RWP.fwd_ntt2(large1);//

                if (compare2(a_0, a_1, large1) == 0)
                {
                    res = 0;
                    break;
                }
            }

            Console.WriteLine("fwd_ntt2: "); 
            if (res == 0)
                Console.WriteLine("BAD!\n");
            else
                Console.WriteLine("OK!\n");/**/



            int fail = 0;
            for (i = 0; i < 20; i++)
            {
                if ((i % 1000) == 0)
                    Console.WriteLine(".");
                
                RWP.seed(i * i);

                if (i == 0)
                {
                    for (j = 0; j < Globals.M; j++)
                    {
                        if (j < Globals.M / 2)
                            large_m[j] = 1;
                        else
                            large_m[j] = 0;
                        
                        large_a[j] = 1;
                        large_p[j] = 1;
                        large_r2[j] = 1;
                    }
                    RWP.bitreverse2(large_m);
                }
                else
                {
                    RWP.message_gen2(large_m);
                    RWP.bitreverse2(large_m);
                    // https://eprint.iacr.org/2014/725.pdf 2.1
                    // KeyGeneration(~a): Two polynomials r1 and r2 are sampled from X using a discrete Gaussian sampler. The following computations are performed.
                    //~ r1 <-  NTT(r1); ~ r2  <- NTT(r2); ~ p1 <-  ~ r1 <- ~a  ~ r2
                    //The private key is ~ r2 and the public key is (~a, ~p).
                    //a=large, p=large2, r2=large3
                    RWP.key_gen2(large_a, large_p, large_r2);
                }
                // Encryption(~a, ~p,m): The input message m is encoded to a polynomial m 2 Rq.
                // Error polynomials e1, e2, e3 2 Rq are generated from X using a discrete Gaussian sampler. 
                // The following computations are performed to compute the ciphertext ( ~ c1, ~ c2).
                // public a + p, ciphertext c1 + c2, message m
                //e1   NTT(e1); ~ e2   NTT(e2)
                //( ~ c1, ~ c2)  <- ~a  ~ e1 + ~ e2; ~p  ~ e1 + NTT(e3 + m)
                // pub a + p, message m, ciphertest c1 + c2
                RWP.RLWE_enc2(large_a, large_c1, large_c2, large_m, large_p);
                //Decryption( ~ c1, ~ c2, ~ r2): The inverse NTT is performed to computem0 = INTT( ~ c1 ~ r2 + ~ c2) 2 Rq. 
                //The original message m is recovered from m0 by using a decoder.
                //We use the parameter sets (n, q, ) from [3], namely P1 = (256, 7 681, 11.31 /log2pi)
                //and P2 = (512, 12 289, 12.18 /log 2pi) that have medium-term and long-term security respectively.
                // ciphertext c1 + c2, private = r2
                RWP.RLWE_dec2(large_c1, large_c2, large_r2);

                for (j = 0; j < Globals.M; j++)
                {
                    if ((large_c1[j] > Globals.QBY4) && (large_c1[j] < Globals.QBY4_TIMES3))
                        large_c1[j] = 1;
                    else
                        large_c1[j] = 0;
                }

                //Determine if the decryption was correct:
                RWP.bitreverse2(large_m);
                RWP.rearrange_for_final_test(large_c1, large1, Globals.M);
                for (j = 0; j < Globals.M; j++)
                {
                    if (large_m[j] != large1[j])
                    {
                        fail = 1;
                        break;
                    }
                }
                if (fail == 1)
                    break;

                for (j = 0; j < 64; j++)
                {
                    if ((large_c1[4 * j] != large_m[2 * j]) || (large_c1[4 * j + 2] != large_m[2 * j + 1]))
                    {
                        Console.WriteLine("Error1!! i=%d,j=%d", i, j);
                        fail = 1;
                        break;
                    }
                    if ((large_c1[4 * j + 1] != large_m[2 * (j + 64)]) || (large_c1[4 * j + 3] != large_m[2 * (j + 64) + 1]))
                    {
                        Console.WriteLine("Error2!! i=%d,j=%d", i, j);
                        fail = 1;
                        break;
                    }
                }
            }

            Console.WriteLine("enc/dec: "); 
            if (fail == 1)
                Console.WriteLine("BAD!\n");
            else
                Console.WriteLine("OK!\n");


            fail = 0;
            for (i = 0; i < 1000; i++)
            {
                large1 = new uint[Globals.M];
                large2 = new uint[Globals.M];
                uint[] large3 = new uint[Globals.M];
                uint[] large7 = new uint[Globals.M];
                uint[] large8 = new uint[Globals.M];
                uint[] tmp_m = new uint[Globals.M];

                //Test knuth-yao
                RWP.seed(i * i);
                //srand(i);
                for (j = 0; j < Globals.M; j++)
                {
                    large1[j] = RWP.get_rand() & 0x1fff;
                    large2[j] = RWP.get_rand() & 0x1fff;
                    large3[j] = RWP.get_rand() & 0x1fff;
                }

                //coefficient_mul2(tmp_m,a,e1); 		            // tmp_m <-- a*e1
                //coefficient_add2(c1, e2, tmp_m);	                // c1 <-- e2 <-- e2 + a*e1(tmp_m);
                RWP.coefficient_mul2(tmp_m, large1, large2); 		// tmp_m <-- a*e1
                RWP.coefficient_add2(large7, tmp_m, large3);
                RWP.coefficient_mul_add2(large8, large1, large2, large3);

                for (j = 0; j < Globals.M; j++)
                {
                    if (large7[j] != large8[j])
                    {
                        fail = 1;
                        break;
                    }
                }
            }

            Console.WriteLine("coefficient_mul_add: "); 
            if (fail == 1)
                Console.WriteLine("BAD!\n");
            else
                Console.WriteLine("OK!\n");/**/

            return 1;
        }

        private byte[] Decode(uint[] a)
        {
            byte[] r = new byte[a.Length / 8];
            for (int i = 0, j = 0; i < r.Length; i++, j += 8)
            {
                r[i] = (byte)((a[j]) << 7 |
                    (a[j + 1]) << 6 |
                    (a[j + 2]) << 5 |
                    (a[j + 3]) << 4 |
                    (a[j + 4]) << 3 |
                    (a[j + 5]) << 2 |
                    (a[j + 6]) << 1 |
                    a[j + 7]);

            }
            return r;
        }

        private uint[] Encode(byte[] a)
        {
            uint[] r = new uint[a.Length * 8];
            for (int i = 0, j = 0; i < a.Length; i++, j += 8)
            {
                r[j] = (uint)a[i] >> 7 & 1;
                r[j + 1] = (uint)a[i] >> 6 & 1;
                r[j + 2] = (uint)a[i] >> 5 & 1;
                r[j + 3] = (uint)a[i] >> 4 & 1;
                r[j + 4] = (uint)a[i] >> 3 & 1;
                r[j + 5] = (uint)a[i] >> 2 & 1;
                r[j + 6] = (uint)a[i] >> 1 & 1;
                r[j + 7] = (uint)a[i] & 1;
            }
            return r;
        }

        private int compare2(uint[] a_0, uint[] a_1, uint[] large)
        {
            int j;
            for (j = 0; j < 128; j++)
            {
                if ((large[2 * j] != a_0[j]) || (large[2 * j + 1] != a_1[j]))
                {
                    Console.WriteLine("j=%d", j);
                    return 0;
                }
            }

            return 1;
        }

    }
}
