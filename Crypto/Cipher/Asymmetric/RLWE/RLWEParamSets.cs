#region Directives
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Principal Algorithms:
// The Ring-LWE Asymmetric Cipher
// 
// Implementation Details:
// An implementation based on the description in the paper 'Efficient Software Implementation of Ring-LWE Encryption' 
// https://eprint.iacr.org/2014/725.pdf and accompanying Github project: https://github.com/ruandc/Ring-LWE-Encryption
// Written by John Underhill, June 8, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE
{
    /// <summary>
    /// Contains sets of predefined Ring-LWE parameters
    /// <para>Use the FromId(byte[]) or FromName(RLWEParamSets) to return a deep copy of a parameter set</para>
    /// </summary>
    /// 
    /// <remarks>
    /// <description><h4>Ring-LWE Parameter Description:</h4></description>
    /// <list type="table">
    /// <item><description>N - The number of coefficients.</description></item>
    /// <item><description>Q - The Q modulus.</description></item>
    /// <item><description>Sigma - The Sigma value.</description></item>
    /// <item><description>OId - Three bytes that uniquely identify the parameter set.</description></item>
    /// <item><description>MFP - The number of random bytes to prepend to the message.</description></item>
    /// <item><description>Engine - The Prng engine.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Efficient Software Implementation of Ring-LWE Encryption<cite>Ring-LWE Encryption</cite>.</description></item>
    /// <item><description>Compact Ring-LWE Cryptoprocessor<cite>Ring-LWE Cryptoprocessor</cite>.</description></item>
    /// <item><description>A Simple Provably Secure Key Exchange Scheme Based on the Learning with Errors Problem<cite>RLWE Scheme</cite>.</description></item>
    /// <item><description>The Knuth-Yao Quadrangle-Inequality Speedup is a Consequence of Total-Monotonicity<cite>Knuth-Yao Quadrangle-Inequality Speedup</cite>.</description></item>
    /// </list>
    /// </remarks>
    public static class RLWEParamSets
    {
        #region Enums
        /// <summary>
        /// Set id is defined as: N: coefficients, Q: Modulus</para>
        /// </summary>
        public enum RLWEParamNames : int
        {
            /// <summary>
            /// Low security; uses CSPRng as the default Prng.
            /// <para>Security:128, MaxText:32, N:256 Q:7681, S:11.31, PublicKey Size:1036, PrivateKey Size:520:</para>
            /// </summary>
            N256Q7681,
            /// <summary>
            /// High security; uses CSPRng as the default Prng.
            /// <para>Security:256, MaxText:64, N:512 Q:12289, S:12.18, PublicKey Size:2060, PrivateKey Size:1032</para>
            /// </summary>
            N512Q12289,
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Retrieve a parameter set by its identity code
        /// </summary>
        /// 
        /// <param name="OId">The 3 byte parameter set identity code</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="RLWEException">Thrown if an invalid or unknown OId is used.</exception>
        public static RLWEParameters FromId(byte[] OId)
        {
            if (OId == null)
                throw new RLWEException("OId can not be null!");
            if (OId.Length != 3)
                throw new RLWEException("OId must be 3 bytes in length!");
            if (OId[0] != 2)
                throw new RLWEException("OId is not a valid RLWE parameter id!");

            if (OId[2] == 0)
                return (RLWEParameters)RLWEN256Q7681.Clone();
            else if (OId[2] == 1)
                return (RLWEParameters)RLWEN512Q12289.Clone();

            throw new RLWEException("OId does not identify a valid param set!");
        }

        /// <summary>
        /// Retrieve a parameter set by its enumeration name
        /// </summary>
        /// 
        /// <param name="Name">The enumeration name</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="RLWEException">Thrown if an invalid or unknown OId is used.</exception>
        public static RLWEParameters FromName(RLWEParamNames Name)
        {
            switch (Name)
            {
                case RLWEParamNames.N256Q7681:
                    return (RLWEParameters)RLWEN256Q7681.Clone();
                case RLWEParamNames.N512Q12289:
                    return (RLWEParameters)RLWEN512Q12289.Clone();
                default:
                    return (RLWEParameters)RLWEN512Q12289.Clone();
            }
        }
        #endregion

        #region Parameter Sets
        // Note: Oid = family, N-base, ordinal
        /// <summary>
        /// Low security; uses CSPRng as the default Prng.
        /// <para>Security:128, MaxText:32, N:256 Q:7681, S:11.31, PublicKey Size:1036, PrivateKey Size:520</para>
        /// </summary>
        public static RLWEParameters RLWEN256Q7681 = new RLWEParameters(256, 7681, 11.31, new byte[] { 2, 2, 0 });

        /// <summary>
        /// High security; uses CSPRng as the default Prng.
        /// <para>Security:256, MaxText:64, N:512 Q:12289, S:12.18, PublicKey Size:2060, PrivateKey Size:1032</para>
        /// </summary>
        public static RLWEParameters RLWEN512Q12289 = new RLWEParameters(512, 12289, 12.18, new byte[] { 2, 5, 1 });
        #endregion
    }
}
