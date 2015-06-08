#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
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
    /// This class implements key pair generation of the Ring-LWE Public Key Cryptosystem.
    /// </summary>
    /// <example>
    /// <description>Example of creating a keypair:</description>
    /// <code>
    /// RLWEParameters encParams = RLWEParameters(512, 12289, 12.18, new byte[] { 2, 5, 1 }))
    /// RLWEKeyGenerator keyGen = new RLWEKeyGenerator(encParams);
    /// IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    ///     <revision date="2015/06/07" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE.RLWEEncrypt">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE RLWEEncrypt Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE.RLWEPublicKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE RLWEPublicKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE.RLWEPrivateKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE RLWEPrivateKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKeyPair Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKey Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prngs">VTDev.Libraries.CEXEngine.Crypto.Prngs Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>Efficient Software Implementation of Ring-LWE Encryption<cite>Ring-LWE Encryption</cite>.</description></item>
    /// <item><description>Compact Ring-LWE Cryptoprocessor<cite>Ring-LWE Cryptoprocessor</cite>.</description></item>
    /// <item><description>A Simple Provably Secure Key Exchange Scheme Based on the Learning with Errors Problem<cite>RLWE Scheme</cite>.</description></item>
    /// <item><description>The Knuth-Yao Quadrangle-Inequality Speedup is a Consequence of Total-Monotonicity<cite>Knuth-Yao Quadrangle-Inequality Speedup</cite>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class RLWEKeyGenerator
    {
        #region Fields
        private RLWEParameters _rlweParams;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CiphersParams">The RLWEParameters instance containing thecipher settings</param>
        /// <param name="OID">The unique id of these keys</param>
        public RLWEKeyGenerator(RLWEParameters CiphersParams)
        {
            if (CiphersParams.RandomEngine == Prngs.PSBPrng)
                throw new RLWEException("Passphrase based Prng is not valid for key generation!");

            _rlweParams = CiphersParams;
        }

        private RLWEKeyGenerator()
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Generate an encryption Key pair
        /// </summary>
        /// 
        /// <returns>A RLWEKeyPair containing public and private keys</returns>
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            if (_rlweParams.N == 512)
                return new NTT512(GetPrng(_rlweParams.RandomEngine)).Generate();
            else
                return new NTT256(GetPrng(_rlweParams.RandomEngine)).Generate();
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="Engine">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        private IRandom GetPrng(Prngs Engine)
        {
            switch (Engine)
            {
                case Prngs.BBSG:
                    return new BBSG();
                case Prngs.CCG:
                    return new CCG();
                case Prngs.CSPRng:
                    return new CSPRng();
                case Prngs.MODEXPG:
                    return new MODEXPG();
                case Prngs.QCG1:
                    return new QCG1();
                case Prngs.QCG2:
                    return new QCG2();
                default:
                    return new CSPRng();
            }
        }
        #endregion
    }
}
