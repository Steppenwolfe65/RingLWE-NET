﻿#region Directives
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
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
    /// An Ring-LWE Key-Pair container
    /// </summary>
    public sealed class RLWEKeyPair : IAsymmetricKeyPair
    {
        #region Fields
        private IAsymmetricKey _publicKey;
        private IAsymmetricKey _privateKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the public key parameters
        /// </summary>
        public IAsymmetricKey PublicKey
        {
            get { return _publicKey; }
        }

        /// <summary>
        /// Get: Returns the private key parameters
        /// </summary>
        public IAsymmetricKey PrivateKey
        {
            get { return _privateKey; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="PublicKey">The public key</param>
        /// <param name="PrivateKey">The corresponding private key</param>
        /// 
        /// <exception cref="RLWEException">Thrown if an invalid key is used</exception>
        public RLWEKeyPair(IAsymmetricKey PublicKey, IAsymmetricKey PrivateKey)
        {
            if (!(PublicKey is RLWEPublicKey))
                throw new RLWEException("RLWEKeyPair:Ctor", "Not a valid RLWE Public key!", new InvalidDataException());
            if (!(PrivateKey is RLWEPrivateKey))
                throw new RLWEException("RLWEKeyPair:Ctor", "Not a valid RLWE Private key!", new InvalidDataException());

            _publicKey = (RLWEPublicKey)PublicKey;
            _privateKey = (RLWEPrivateKey)PrivateKey;
            _publicKey = PublicKey;
            _privateKey = PrivateKey;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Key">The public or private key</param>
        /// 
        /// <exception cref="RLWEException">Thrown if an invalid key is used</exception>
        public RLWEKeyPair(IAsymmetricKey Key)
        {
            if (Key is RLWEPublicKey)
                _publicKey = (RLWEPublicKey)Key;
            else if (Key is RLWEPrivateKey)
                _privateKey = (RLWEPrivateKey)Key;
            else
                throw new RLWEException("RLWEKeyPair:Ctor", "Not a valid RLWE key!", new InvalidDataException());
        }

        private RLWEKeyPair()
        {
        }
        #endregion
    }
}
