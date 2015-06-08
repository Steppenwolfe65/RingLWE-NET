using System;
using VTDev.Libraries.CEXEngine.Utility;

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE
{
    internal class Lwe
    {
        #region Fields
        Random secRand = new Random(0);
        #endregion

        #region Implementation 1
        internal void a_gen(uint[] a_0, uint[] a_1)
        {
            uint r;

            for (int i = 0; i < Globals.M / 2; i++)
            {
                r = get_rand();//rand();
                a_0[i] = mod((int)r & 0xffff);
                a_1[i] = mod((int)IntUtils.URShift(r, 16));
            }

            fwd_ntt(a_0, a_1);
        }

        void coefficient_add(uint[] a_0, uint[] a_1, uint[] b_0, uint[] b_1)
        {
            for (int j = 0; j < Globals.M / 2; j++)
            {
                a_0[j] = a_0[j] + b_0[j];
                a_0[j] = mod((int)a_0[j]);
                a_1[j] = a_1[j] + b_1[j];
                a_1[j] = mod((int)a_1[j]);
            }
        }

        void coefficient_mul(uint[] a_0, uint[] a_1, uint[] b_0, uint[] b_1)
        {
            for (int j = 0; j < Globals.M / 2; j++)
            {
                a_0[j] = a_0[j] * b_0[j];
                a_0[j] = mod((int)a_0[j]);
                a_1[j] = a_1[j] * b_1[j];
                a_1[j] = mod((int)a_1[j]);
            }
        }

        void coefficient_sub(uint[] a_0, uint[] a_1, uint[] b_0, uint[] b_1)
        {
            for (int j = 0; j < Globals.M / 2; j++)
            {
                a_0[j] = a_0[j] - b_0[j];
                a_0[j] = mod((int)a_0[j]);
                a_1[j] = a_1[j] - b_1[j];
                a_1[j] = mod((int)a_1[j]);
            }
        }

        internal void fwd_ntt(uint[] a_0, uint[] a_1)
        {
            int i, j, k, m;
            uint u1, t1, u2, t2;
            uint primrt = 0, omega = 0;

            //primitive root = 5118
            //square_root = 1065

            for (m = 2; m <= Globals.M / 2; m = 2 * m)
            {
                if (m == 2)
                    primrt = 7680;
                else if
                    (m == 4) primrt = 4298;
                else if
                    (m == 8) primrt = 6468;
                else if
                    (m == 16) primrt = 849;
                else if
                    (m == 32) primrt = 2138;
                else if
                    (m == 64) primrt = 3654;
                else if (m == 128)
                    primrt = 1714;

                if (m == 2)
                    omega = 4298;
                else if (m == 4)
                    omega = 6468;
                else if (m == 8)
                    omega = 849;
                else if (m == 16)
                    omega = 2138;
                else if (m == 32)
                    omega = 3654;
                else if (m == 64)
                    omega = 1714;
                else if (m == 128)
                    omega = 5118;


                for (j = 0; j < m / 2; j++)
                {
                    for (k = 0; k < 128; k = k + m)
                    {
                        t1 = omega * a_1[k + j];
                        t1 = mod((int)t1);
                        t2 = omega * a_1[k + j + m / 2];
                        t2 = mod((int)t2);
                        u1 = a_0[k + j];
                        u2 = a_0[k + j + m / 2];
                        a_0[k + j] = u1 + t1;
                        a_0[k + j] = mod((int)a_0[k + j]);
                        a_1[k + j] = u2 + t2;
                        a_1[k + j] = mod((int)a_1[k + j]);
                        a_0[k + j + m / 2] = u1 - t1;
                        a_0[k + j + m / 2] = mod((int)a_0[k + j + m / 2]);
                        a_1[k + j + m / 2] = u2 - t2;
                        a_1[k + j + m / 2] = mod((int)a_1[k + j + m / 2]);
                    }
                    omega = omega * primrt;
                    omega = mod((int)omega);
                }
            }

            primrt = 5118;
            omega = 1065;

            for (j = 0; j < Globals.M / 2; j++)
            {
                t1 = omega * a_1[j];
                t1 = mod((int)t1);
                u1 = a_0[j];
                a_0[j] = u1 + t1;
                a_0[j] = mod((int)a_0[j]);
                a_1[j] = u1 - t1;
                a_1[j] = mod((int)a_1[j]);
                omega = omega * primrt;
                omega = mod((int)omega);
            }
        }

        internal void knuth_yao(uint[] e_0, uint[] e_1)
        {
            uint rnd = get_rand();

            for (int i = 0; i < 128; i++)
            {
                e_0[i] = knuth_yao_single_number(ref rnd);
                e_1[i] = knuth_yao_single_number(ref rnd);
            }
        }

        internal uint knuth_yao_single_number(ref uint rnd)
        {
            int distance;
            int row, column;
            int index, sample, sample_msb;

            index = (int)rnd & 0xff;
            rnd >>= 8;
            sample = Luts.lut1[index]; //M elements in lut1
            sample_msb = sample & 16;

            if (sample_msb == 0)	  //lookup was successful
            {
                if (rnd == Globals.NEW_RND_BOTTOM)
                    rnd = get_rand();

                sample &= 0xf;
                if ((rnd & 1) != 0)
                    sample = (Globals.MODULUS - sample); //9th bit in rnd is the sign

                rnd >>= 1;
                //We know that in the next call we will need 8 bits!
                if (clz(rnd) > (Globals.NEW_RND_LARGE))
                    rnd = get_rand();

                return (uint)sample;
            }
            else
            {
                if (clz(rnd) > (Globals.NEW_RND_MID))
                    rnd = get_rand();

                distance = sample & Globals.KN_DISTANCE1_MASK;
                //index = rnd&0xff;
                //index = state1[15] + 2*state2[15] + 4*state3[15] + 8*state4[15] + 16*state5[15] + 32*distance;
                index = (int)(rnd & 0x1f) + 32 * distance;
                rnd >>= 5;

                if (rnd == Globals.NEW_RND_BOTTOM)
                    rnd = get_rand();

                sample = Luts.lut2[index]; //224 elements in lut2
                sample_msb = sample & 32;

                if (sample_msb == 0)	// lookup was successful
                {
                    sample = sample & 31;
                    if ((rnd & 1) != 0)
                        sample = (Globals.MODULUS - sample); //9th bit in rnd is the sign

                    rnd = rnd >> 1;
                    if (clz(rnd) > (Globals.NEW_RND_LARGE))
                        rnd = get_rand();

                    return (uint)sample;
                }
                else
                {
                    //Real knuth-yao
                    distance = sample & Globals.KN_DISTANCE2_MASK;
                    for (column = 13; (column < Globals.PMAT_MAX_COL); column++)
                    {
                        distance = (int)(distance * 2 + (rnd & 1));
                        rnd = rnd >> 1;
                        if (rnd == Globals.NEW_RND_BOTTOM)
                            rnd = get_rand();

                        // Read probability-column 0 and count the number of non-zeros
                        for (row = 54; row >= 0; row--)
                        {
                            distance = distance - Luts.pmat[row][column];
                            if (distance < 0)
                            {
                                if ((rnd & 1) != 0)
                                    sample = (Globals.MODULUS - row);
                                else
                                    sample = row;

                                rnd = rnd >> 1;
                                if (clz(rnd) > (Globals.NEW_RND_LARGE))
                                    rnd = get_rand();

                                return (uint)sample;
                            }
                        }
                        //rnd = rnd >> 1;
                    }
                }
            }

            return 0;
        }

        void rearrange(int[] a_0, int[] a_1)
        {
            int i;
            int bit1, bit2, bit3, bit4, bit5, bit6, bit7;
            int swp_index;

            int u1, u2;

            for (i = 0; i < Globals.M / 2; i++)
            {
                bit1 = i % 2;
                bit2 = IntUtils.URShift(i, 1) % 2;
                bit3 = IntUtils.URShift(i, 2) % 2;
                bit4 = IntUtils.URShift(i, 3) % 2;
                bit5 = IntUtils.URShift(i, 4) % 2;
                bit6 = IntUtils.URShift(i, 5) % 2;
                bit7 = IntUtils.URShift(i, 6) % 2;

                swp_index = bit1 * 64 + bit2 * 32 + bit3 * 16 + bit4 * 8 + bit5 * 4 + bit6 * 2 + bit7;

                if (swp_index > i)
                {
                    u1 = a_0[i];
                    u2 = a_1[i];

                    a_0[i] = a_0[swp_index];
                    a_1[i] = a_1[swp_index];

                    a_0[swp_index] = u1;
                    a_1[swp_index] = u2;
                }
            }
        }
        #endregion

        #region Implementation 2
        internal void a_gen2(uint[] a)
        {
            int i, r;

            for (i = 0; i < Globals.M / 2; i++)
            {
                r = (int)get_rand();
                a[2 * i] = mod(r & 0xffff);
                a[2 * i + 1] = mod(IntUtils.URShift(r, 16));
            }

            fwd_ntt2(a);
        }

        internal void coefficient_add2(uint[] a, uint[] b, uint[] c)
        {
            for (int j = 0; j < Globals.M; j++)
            {
                a[j] = b[j] + c[j];
                a[j] = mod((int)a[j]);
            }
        }

        internal void coefficient_mul2(uint[] a, uint[] b, uint[] c)
        {
            for (int j = 0; j < Globals.M; j++)
            {
                a[j] = b[j] * c[j];
                a[j] = mod((int)a[j]);
            }
        }

        internal void coefficient_mul_add2(uint[] result, uint[] large1, uint[] large2, uint[] large3)
        {
            for (int j = 0; j < Globals.M; j++)
            {
                result[j] = large1[j] * large2[j];
                result[j] = result[j] + large3[j];
                result[j] = mod((int)result[j]);
            }
        }

        void coefficient_sub2(uint[] a, uint[] b, uint[] c)
        {
            for (int j = 0; j < Globals.M; j++)
            {
                a[j] = b[j] - c[j];
                a[j] = mod((int)a[j]);
            }
        }

        internal void RLWE_dec2(uint[] c1, uint[] c2, uint[] r2)
        {
            coefficient_mul2(c1, c1, r2);	// c1 <-- c1*r2
            coefficient_add2(c1, c1, c2);	// c1 <-- c1*r2 + c2

            inv_ntt2(c1);
        }

        internal void RLWE_enc2(uint[] a, uint[] c1, uint[] c2, uint[] m, uint[] p)
        {
            int i;
            uint[] e1 = new uint[Globals.M], e2 = new uint[Globals.M], e3 = new uint[Globals.M];
            uint[] encoded_m = new uint[Globals.M];

            for (i = 0; i < Globals.M; i++)
                encoded_m[i] = m[i] * Globals.QBY2;// Globals.QBY2;		// encoding of message

            knuth_yao2(e1);
            knuth_yao2(e2);
            knuth_yao2(e3);

            coefficient_add2(e3, e3, encoded_m);	// e3 <-- e3 + m

            fwd_ntt2(e1);
            fwd_ntt2(e2);
            fwd_ntt2(e3);

            // m <-- a*e1
            coefficient_mul2(c1, a, e1); 		// c1 <-- a*e1
            coefficient_add2(c1, e2, c1);	    // c1 <-- e2 + a*e1(tmp_m);
            coefficient_mul2(c2, p, e1); 		// c2 <-- p*e1
            coefficient_add2(c2, e3, c2);	    // c2<-- e3 + p*e1

            rearrange2(c1);
            rearrange2(c2);
        }

        internal void fwd_ntt2(uint[] a)
        {
            int i, j, k, m;
            int u1, t1, u2, t2;
            int primrt, omega;

            i = 0;
            for (m = 2; m <= Globals.M / 2; m = 2 * m)
            {
                primrt = Luts.primrt_omega_table[i];
                omega = Luts.primrt_omega_table[i + 1];
                i++;

                for (j = 0; j < m; j += 2)
                {
                    for (k = 0; k < Globals.M; k = k + 2 * m)
                    {
                        u1 = (int)a[j + k];
                        t1 = (int)mod(omega * (int)a[j + k + 1]);
                        u2 = (int)a[j + k + m];
                        t2 = (int)mod(omega * (int)a[j + k + m + 1]);
                        a[j + k] = mod(u1 + t1);
                        a[j + k + 1] = mod(u2 + t2);
                        a[j + k + m] = mod(u1 - t1);
                        a[j + k + m + 1] = mod(u2 - t2);
                    }

                    omega = omega * primrt;
                    omega = (int)mod(omega);
                }
            }

            primrt = Globals.FWD_CONST1; 	//mpz_set_str(primrt,"5118",10);
            omega = Globals.FWD_CONST2;	//mpz_set_str(omega,"1065",10);

            for (j = 0; j < Globals.M / 2; j++)
            {
                t1 = omega * (int)a[2 * j + 1];
                t1 = (int)mod(t1);
                u1 = (int)a[2 * j];
                a[2 * j] = (uint)(u1 + t1);
                a[2 * j] = mod((int)a[2 * j]);
                a[2 * j + 1] = (uint)(u1 - t1);
                a[2 * j + 1] = mod((int)a[2 * j + 1]);

                omega = omega * primrt;
                omega = (int)mod(omega);
            }
        }

        internal void inv_ntt2(uint[] a)
        {
            int i, j, k, m;
            int u1, t1, u2, t2;
            int primrt = 0, omega = 0;

            for (m = 2; m <= Globals.M / 2; m = 2 * m)
            {
#if NTT512
		        switch (m)
		        {
			        case 2: primrt=12288;
					        break;
			        case 4: primrt=10810;
					        break;
			        case 8: primrt=7143;
					        break;
			        case 16:primrt=10984;
					        break;
			        case 32:primrt=3542;
					        break;
			        case 64:primrt=4821;
					        break;
			        case 128:primrt=1170;
					        break;
			        case 256:primrt=5755;
					        break;
		        }
#else
                switch (m)
                {
                    case 2: primrt = 7680;
                        break;
                    case 4: primrt = 3383;
                        break;
                    case 8: primrt = 5756;
                        break;
                    case 16: primrt = 1728;
                        break;
                    case 32: primrt = 7584;
                        break;
                    case 64: primrt = 6569;
                        break;
                    case 128: primrt = 6601;
                        break;
                }
#endif

                omega = 1;
                for (j = 0; j < m / 2; j++)
                {
                    for (k = 0; k < Globals.M / 2; k = k + m)
                    {
                        t1 = omega * (int)a[2 * (k + j) + 1];
                        t1 = (int)mod(t1);
                        u1 = (int)a[2 * (k + j)];
                        t2 = omega * (int)a[2 * (k + j + m / 2) + 1];
                        t2 = (int)mod(t2);
                        u2 = (int)a[2 * (k + j + m / 2)];

                        a[2 * (k + j)] = (uint)(u1 + t1);
                        a[2 * (k + j)] = mod((int)a[2 * (k + j)]);
                        a[2 * (k + j + m / 2)] = (uint)(u1 - t1);
                        a[2 * (k + j + m / 2)] = mod((int)a[2 * (k + j + m / 2)]);

                        a[2 * (k + j) + 1] = (uint)(u2 + t2);
                        a[2 * (k + j) + 1] = mod((int)a[2 * (k + j) + 1]);
                        a[2 * (k + j + m / 2) + 1] = (uint)(u2 - t2);
                        a[2 * (k + j + m / 2) + 1] = mod((int)a[2 * (k + j + m / 2) + 1]);
                    }
                    omega = omega * primrt;
                    omega = (int)mod(omega);
                }
            }

            primrt = Globals.INVCONST1;
            omega = 1;
            for (j = 0; j < Globals.M; )
            {
                u1 = (int)a[j];
                j++;
                t1 = (int)(omega * a[j]);
                t1 = (int)mod(t1);

                a[j - 1] = (uint)(u1 + t1);
                a[j - 1] = mod((int)a[j - 1]);
                a[j] = (uint)(u1 - t1);
                a[j] = mod((int)a[j]);
                j++;

                omega = omega * primrt;
                omega = (int)mod(omega);
            }
            int omega2 = Globals.INVCONST2;
            primrt = Globals.INVCONST3;
            omega = 1;

            for (j = 0; j < Globals.M; )
            {
                a[j] = (uint)omega * a[j];
                a[j] = mod((int)a[j]);
                a[j] = a[j] * Globals.SCALING;
                a[j] = mod((int)a[j++]);
                a[j] = (uint)omega2 * a[j];
                a[j] = mod((int)a[j]);
                a[j] = a[j] * Globals.SCALING;
                a[j] = mod((int)a[j++]);

                omega = omega * primrt;
                omega = (int)mod(omega);
                omega2 = omega2 * primrt;
                omega2 = (int)mod(omega2);
            }
            /*
            omega = 1;
            for(j=0; j<Globals.M; j++)
            {
                a[j] = a[j] * 7651;
                a[j] = mod(a[j]);
            }*/
        }

        internal void key_gen2(uint[] a, uint[] p, uint[] r2)
        {
            a_gen2(a);
            r1_gen2(p);
            r2_gen2(r2, Globals.MODULUS);

            uint[] tmp_a = new uint[Globals.M];
            //a = a*r2
            coefficient_mul2(tmp_a, a, r2);
            //p = p-a*r2
            coefficient_sub2(p, p, tmp_a);

            rearrange2(r2);
        }

        internal void knuth_yao2(uint[] a)
        {
            uint rnd = get_rand();

            for (int i = 0; i < Globals.M / 2; i++)
            {
                a[2 * i + 1] = knuth_yao_single_number(ref rnd);
                a[2 * i] = knuth_yao_single_number(ref rnd);
            }
        }

        internal void knuth_yao_smaller_tables2(uint[] a)
        {
            uint rnd = get_rand();

            for (int i = 0; i < Globals.M / 2; i++)
            {
                a[2 * i + 1] = knuth_yao_smaller_tables_single_number(ref rnd);
                a[2 * i] = knuth_yao_smaller_tables_single_number(ref rnd);
            }
        }

        internal uint knuth_yao_smaller_tables_single_number(ref uint rnd)
        {
            int distance, row, column, index, sample, sample_msb;
            int high, low;

            index = (int)rnd & 0xff;//255
            rnd = rnd >> 8;//63
            sample = Luts.lut1[index]; //Globals.M elements in lut1//22
            sample_msb = sample & 16;

            if (sample_msb == 0)	  //lookup was successful
            {
                if (rnd == Globals.NEW_RND_BOTTOM)
                    rnd = get_rand();

                //9th bit in rnd is the sign
                sample = sample & 0xf;
                if ((rnd & 1) != 0)
                    sample = (Globals.MODULUS - sample);

                rnd = rnd >> 1;
                //We know that in the next call we will need 8 bits!
                if (clz(rnd) > (Globals.NEW_RND_LARGE))
                    rnd = get_rand();

                return (uint)sample;
            }
            else
            {
                if (clz(rnd) > (Globals.NEW_RND_MID))
                    rnd = get_rand();

                distance = sample & Globals.KN_DISTANCE1_MASK;//6
                //index = rnd&0xff;
                //index = state1[15] + 2*state2[15] + 4*state3[15] + 8*state4[15] + 16*state5[15] + 32*distance;
                index = (int)(rnd & 0x1f) + 32 * distance;//223
                rnd = rnd >> 5;//1

                if (rnd == Globals.NEW_RND_BOTTOM)
                    rnd = get_rand();//318..503
                sample = Luts.lut2[index]; //224 elements in lut2 //42
                sample_msb = sample & 32;

                if (sample_msb == 0)	// lookup was successful
                {
                    sample = sample & 31;
                    //9th bit in rnd is the sign
                    if ((rnd & 1) != 0)
                        sample = (Globals.MODULUS - sample);

                    rnd = rnd >> 1;
                    if (clz(rnd) > (Globals.NEW_RND_LARGE))
                        rnd = get_rand();

                    return (uint)sample;
                }
                else
                {
                    //Real knuth-yao
                    distance = sample & Globals.KN_DISTANCE2_MASK;

                    //NB: Need to update PMAT_MAX_COL!
                    for (column = 0; column < 96/*Globals.PMAT_MAX_COL*/; column++)//ToDo: ju
                    {
                        distance = (int)(distance * 2 + (rnd & 1));
                        rnd = rnd >> 1;
                        if (rnd == Globals.NEW_RND_BOTTOM)
                            rnd = get_rand();

                        //high=pmat_cols_small_high[column];
                        //low=pmat_cols_small_low[column];
                        low = (int)Luts.pmat_cols_small_low2[column];

                        //if ((int)(distance - Luts.pmat_cols_small_hamming[column]) < 0)
                        //{
                        //Assume that HAMMING_TABLE_SIZE<7 and therefore column<7
                        //pmat_cols_small_high only contains a value when column=8 (Real column 20)
                        //This means that it must be inside the high part
                        //for(row=(54-32); row>=0; row--)
                        for (row = (31); row >= 0; row--)
                        {
                            distance = distance - IntUtils.URShift(low, 31); //subtract the most significant bit
                            low = low << 1;
                            if (distance == -1)
                            {
                                if ((rnd & 1) != 0)
                                    sample = (Globals.MODULUS - row);
                                else
                                    sample = row;
                                rnd = rnd >> 1;
                                if (clz(rnd) > (Globals.NEW_RND_LARGE))
                                {
                                    rnd = get_rand();
                                }
                                return (uint)sample;
                            }
                        }
                        //}
                        //else
                        //{
                        //    distance = (int)(distance - Luts.pmat_cols_small_hamming[column]);
                        //}
                    }
                    for (column = Globals.HAMMING_TABLE_SIZE; (column < (109 - 13)); column++)
                    {
                        //high=pmat_cols_small_high[column];
                        //low=pmat_cols_small_low[column];
                        high = (int)Luts.pmat_cols_small_high2[column];
                        //high=pmat_cols_small_high3[column-25];
                        low = (int)Luts.pmat_cols_small_low2[column];
                        distance = (int)(distance * 2 + (rnd & 1));
                        rnd = rnd >> 1;
                        //if ((column==32)||(column==64)||(column==96))
                        if (rnd == Globals.NEW_RND_BOTTOM)
                            rnd = get_rand();// rand();

                        //for(row=54; row>(54-32); row--)
                        for (row = 54; row >= 32; row--)
                        {
                            distance = distance - IntUtils.URShift(high, 31); //subtract the most significant bit
                            high = high << 1;

                            if (distance == -1)
                            {
                                if ((rnd & 1) != 0)
                                    sample = (Globals.MODULUS - row);
                                else
                                    sample = row;

                                rnd = rnd >> 1;
                                if (clz(rnd) > (Globals.NEW_RND_LARGE))
                                    rnd = get_rand();//rand();

                                return (uint)sample;
                            }
                        }
                        //for(row=(54-32); row>=0; row--)
                        for (row = (31); row >= 0; row--)
                        {
                            distance = distance - IntUtils.URShift(low, 31); //subtract the most significant bit
                            low = low << 1;
                            if (distance == -1)
                            {
                                if ((rnd & 1) != 0)
                                    sample = (Globals.MODULUS - row);
                                else
                                    sample = row;

                                rnd = rnd >> 1;
                                if (clz(rnd) > (Globals.NEW_RND_LARGE))
                                    rnd = get_rand();//rand();

                                return (uint)sample;
                            }
                        }
                    }
                }
            }
            return 0;
        }

        internal void rearrange2(uint[] a)
        {
            int i;
            int bit1, bit2, bit3, bit4, bit5, bit6, bit7, bit8;
            int swp_index;

            int u1, u2;

            for (i = 1; i < a.Length / 2; i++)
            {
                bit1 = i % 2;
                bit2 = (i >> 1) % 2;
                bit3 = (i >> 2) % 2;
                bit4 = (i >> 3) % 2;
                bit5 = (i >> 4) % 2;
                bit6 = (i >> 5) % 2;
                bit7 = (i >> 6) % 2;

#if NTT512
		            bit8 = (i >> 7) % 2;
		            swp_index = bit1 * 128 + bit2 * 64 + bit3 * 32 + bit4 * 16 + bit5 * 8 + bit6 * 4 + bit7 * 2 + bit8;
#else
                    swp_index = bit1 * 64 + bit2 * 32 + bit3 * 16 + bit4 * 8 + bit5 * 4 + bit6 * 2 + bit7;
#endif

                if (swp_index > i)
                {
                    u1 = (int)a[2 * i];
                    u2 = (int)a[2 * i + 1];
                    a[2 * i] = a[2 * swp_index];
                    a[2 * i + 1] = a[2 * swp_index + 1];
                    a[2 * swp_index] = (uint)u1;
                    a[2 * swp_index + 1] = (uint)u2;
                }
            }
        }

        void r1_gen2(uint[] r1)
        {
            knuth_yao2(r1);
            fwd_ntt2(r1);
        }

        void r2_gen2(uint[] r2, int Q)
        {
            int i, j, r, bit, sign;

            for (i = 0; i < Globals.M; )
            {
                r = (int)get_rand();

                for (j = 0; j < 16; j++)
                {
                    bit = r & 1;
                    sign = IntUtils.URShift(r, 1) & 1;
                    if (sign == 1 && bit == 1) bit = (Q - 1);
                    r2[i++] = (uint)bit;
                    r = IntUtils.URShift(r, 2);
                }
            }

            fwd_ntt2(r2);
        }
        #endregion

        #region Common
        internal void bitreverse2(uint[] a)
        {
            int i;
            int bit1, bit2, bit3, bit4, bit5, bit6, bit7, bit8, swp_index;
            int q1, r1, q2, r2;
            int temp = 0;

            for (i = 0; i < Globals.M; i++)
            {
                bit1 = i % 2;
                bit2 = (i >> 1) % 2;
                bit3 = (i >> 2) % 2;
                bit4 = (i >> 3) % 2;
                bit5 = (i >> 4) % 2;
                bit6 = (i >> 5) % 2;
                bit7 = (i >> 6) % 2;
                bit8 = (i >> 7) % 2;

#if NTT512
                    int bit9 = (i >> 8) % 2;
                    swp_index = bit1 * 256 + bit2 * 128 + bit3 * 64 + bit4 * 32 + bit5 * 16 + bit6 * 8 + bit7 * 4 + bit8 * 2 + bit9;
#else
                    swp_index = bit1 * 128 + bit2 * 64 + bit3 * 32 + bit4 * 16 + bit5 * 8 + bit6 * 4 + bit7 * 2 + bit8;
#endif

                q1 = i / 2;
                r1 = i % 2;
                q2 = swp_index / 2;
                r2 = swp_index % 2;

                if (swp_index > i)
                {
                    if (r2 == 0) 
                        temp = (int)a[2 * q2];
                    if (r2 == 1) 
                        temp = (int)a[2 * q2 + 1];
                    if (r2 == 0 && r1 == 0) 
                        a[2 * q2] = a[2 * q1];
                    if (r2 == 0 && r1 == 1) 
                        a[2 * q2] = a[2 * q1 + 1];
                    if (r2 == 1 && r1 == 0) 
                        a[2 * q2 + 1] = a[2 * q1];
                    if (r2 == 1 && r1 == 1) 
                        a[2 * q2 + 1] = a[2 * q1 + 1];
                    if (r1 == 0) 
                        a[2 * q1] = (uint)temp;
                    if (r1 == 1) 
                        a[2 * q1 + 1] = (uint)temp;
                }
            }
        }

        uint clz(uint a)
        {
            int i;
            for (i = 0; i < 32; i++)
            {
                if (IntUtils.URShift(a, (31 - i)) == 1)
                    return (uint)i;
            }
            return 32;
        }

        internal int compare2(uint[] a_0, uint[] a_1, uint[] large)
        {
            for (int j = 0; j < 128; j++)
            {
                if ((large[2 * j] != a_0[j]) || (large[2 * j + 1] != a_1[j]))
                    return 0;
            }

            return 1;
        }

        uint compare_large_simd(uint[] large_simd, uint[] large)
        {
            for (int j = 0; j < Globals.M / 2; j++)
            {
                if (((large_simd[j] & 0xffff) != large[2 * j]))
                {
                    //xprintf("(j_low=%x)",j);
                    return 0;
                }

                if (IntUtils.URShift(large_simd[j], 16) != large[2 * j + 1])
                {
                    //xprintf("(j_high=%x)",j);
                    return 0;
                }
            }

            return 1;
        }

        uint compare_simd(uint[] a_0, uint[] a_1, uint[] large)
        {
            for (int j = 0; j < Globals.M / 2; j++)
            {
                if (((large[j] & 0xffff) != a_0[j]) || (IntUtils.URShift(large[j], 16) != a_1[j]))
                    return 0;
            }

            return 1;
        }

        void get_ntt_random_numbers(uint[] large1, uint[] large2, int i)
        {
            int j;
            uint rnd1, rnd2;

            //srand(i);
            if (i == 0)
            {
                for (j = 0; j < Globals.M / 2; j++)
                {
                    rnd1 = (uint)(j + 1);
                    rnd2 = (uint)(j + 2);
                    large1[j] = (rnd1 & 0xffff) + ((rnd2 & 0xffff) << 16);
                    large2[2 * j] = rnd1;
                    large2[2 * j + 1] = rnd2;
                }
            }
            else
            {
                for (j = 0; j < Globals.M / 2; j++)
                {
                    rnd1 = get_rand() & 0x1FFF;
                    rnd2 = get_rand() & 0x1FFF;
                    large1[j] = (rnd1 & 0xffff) + ((rnd2 & 0xffff) << 16);
                    large2[2 * j] = rnd1;
                    large2[2 * j + 1] = rnd2;
                }
            }
        }

        void get_rand_input(int i, uint[] large1, uint[] large2)
        {
            int rnd1, rnd2, j;
            //srand(i);
            if (i == 0)
            {
                for (j = 0; j < Globals.M / 2; j++)
                {
                    rnd1 = 2 * j;
                    rnd2 = 2 * j + 1;
                    large1[j] = (uint)((rnd1 & 0xffff) + ((rnd2 & 0xffff) << 16));
                    large2[2 * j] = (uint)rnd1;
                    large2[2 * j + 1] = (uint)rnd2;
                }
            }
            else
            {
                for (j = 0; j < Globals.M / 2; j++)
                {
                    rnd1 = (int)(get_rand() & Globals.COEFFICIENT_ALL_ONES);
                    rnd2 = (int)(get_rand() & Globals.COEFFICIENT_ALL_ONES);
                    large1[j] = (uint)((rnd1 & 0xffff) + ((rnd2 & 0xffff) << 16));
                    large2[2 * j] = (uint)rnd1;
                    large2[2 * j + 1] = (uint)rnd2;
                }
            }
        }

        internal uint get_rand()
        {
            uint rnd = (uint)secRand.Next();
            rnd |= 0x80000000; //set the least significant bit
            return rnd;
        }

        internal void message_gen2(uint[] m)
        {
            for (int i = 0; i < Globals.M; i++)
                m[i] = get_rand() % 2;
        }

        uint mod(int a)
        {
            int quotient, remainder;
            quotient = a / Globals.MODULUS;

            if (a >= 0)
                remainder = a - quotient * Globals.MODULUS;
            else
                remainder = (1 - quotient) * Globals.MODULUS + a;

            return (uint)remainder;
        }

        internal void rearrange_for_final_test(uint[] inp, uint[] outp, int M)
        {
            int i;
            for (i = 0; i < M / 2; i += 2)
            {
                outp[i] = inp[2 * i];
                outp[i + 1] = inp[2 * (i + 1)];
            }

            for (i = 0; i < M / 2; i += 2)
            {
                outp[i + M / 2] = inp[2 * i + 1];
                outp[i + 1 + M / 2] = inp[2 * (i + 1) + 1];
            }
        }

        internal void seed(int seed)
        {
            secRand = new Random(seed);
        }
        #endregion
    }
}
