namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE
{
    internal static class Globals
    {
        #region Constants
        internal const int NUMBER_OF_RANDOM_BITS = 10000000;
        internal const int NUMBER_OF_RANDOM_WORDS = NUMBER_OF_RANDOM_BITS / 4;
        internal const bool GENERATE_RANDOM_BITS = false;
        internal const int INNER_REPEAT_COUNT = 1;
        internal const bool USE_PARALLEL = false;
        internal const bool PERFORM_UNIT_TESTS = false;
        internal const bool PERFORM_UNIT_TESTS_BIG = false;
        internal const bool PERFORM_SPEED_TESTS = false;
        internal const bool PERFORM_BIG_SPEED_TESTS = false;
        internal const bool PERFORM_SMALL_SPEED_TESTS = false;
        internal const int UNIT_TEST_BIG_LOOPS = 100;
        internal const int UNIT_TEST_SMALL_LOOPS = 500;
        internal const int SPEED_TEST_BIG_LOOPS = 10000;
        internal const int SPEED_TEST_SMALL_LOOPS = 1000;
        internal const bool USE_TRNG = false;

        internal const int NEW_RND_BOTTOM = 1;
        internal const int NEW_RND_LARGE = 32 - 9;
        internal const int NEW_RND_MID = 32 - 6;

        //internal const bool DISABLE_KNUTH_YAO = false;
        //internal const bool PERFORM_DECRYPTION_ERROR_TEST = false;
        //internal const bool PERFORM_UNIT_TESTS_SMALL = false;

        //internal const bool KNUTH_YAO_512
#if KNUTH_YAO_512
	    internal const int LOW_MSB = 26;
	    internal const int HAMMING_TABLE_SIZE = 10;
	    internal const int PMAT_MAX_COL = 106;
	    internal const int KN_DISTANCE1_MASK = 15;
	    internal const int KN_DISTANCE2_MASK = 15;
#else
        internal const int LOW_MSB = 22;
        internal const int HAMMING_TABLE_SIZE = 8;
        internal const int PMAT_MAX_COL = 109;//96
        internal const int KN_DISTANCE1_MASK = 7;
        internal const int KN_DISTANCE2_MASK = 15;
#endif

        //internal const bool NTT512
#if NTT512
	    internal const int MODULUS = 12289;
	    internal const int M = 512;
	    internal const int UMOD_CONSTANT = 0xAAA71C85;
	    internal const int QBY2 = 6144;
	    internal const int QBY4 = 3072;
	    internal const int QBY4_TIMES3 = 9216;
	    internal const int FWD_CONST1 = 5559;
	    internal const int FWD_CONST2 = 6843;
	    internal const int INVCONST1 = 3778;
	    internal const int INVCONST2 = 10810;
	    internal const int INVCONST3 = 9087;
	    internal const int SCALING = 12265;
	    internal const int COEFFICIENT_ALL_ONES = 0x3FFF;//14 bits
#else
        internal const int MODULUS = 7681;  //q
        internal const int M = 256;         //n
        internal const int UMOD_CONSTANT = 0x4441fdcd;//-
        internal const int QBY2 = 3840; // encoding
        internal const int QBY4 = 1920; // encoding
        internal const int QBY4_TIMES3 = 5760; // encode max
        internal const int FWD_CONST1 = 5118; //primrt in fwdntt2
        internal const int FWD_CONST2 = 1065; //omega in fwdntt
        internal const int INVCONST1 = 2880; //primert1 in invntt2
        internal const int INVCONST2 = 3383; //omega2 in invntt2
        internal const int INVCONST3 = 2481; //primert2 in invntt2
        internal const int SCALING = 7651;
        internal const int COEFFICIENT_ALL_ONES = 0x1FFF;//13 bits
#endif
        #endregion
    }
}
