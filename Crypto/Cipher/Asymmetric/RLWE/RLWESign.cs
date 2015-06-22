#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Exceptions;
using VTDev.Libraries.CEXEngine.Tools;
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
    /// An Ring-LWE One Time Sign (OTS) message sign and verify implementation.
    /// <para>Sign: uses the specified digest to hash a message; the hash value is then encrypted with a RLWE public key.
    /// Verify: decrypts the RLWE cipher text, and then compares the value to a hash of the message.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of using the signing and verifying an array:</description>
    /// <code>
    /// RLWEParameters encParams = RLWEParamSets.RLWEN256Q768;
    /// RLWEKeyGenerator keyGen = new RLWEKeyGenerator(encParams);
    /// IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
    /// byte[] code;
    /// byte[] data = new byte[100];
    ///
    /// // get the message code for an array of bytes
    /// using (RLWESign signer = new RLWESign(encParams))
    /// {
    ///     signer.Initialize(keyPair);
    ///     code = signer.Sign(data, 0, data.Length);
    /// }
    ///
    /// // test the message for validity
    /// using (RLWESign signer = new RLWESign(encParams))
    /// {
    ///     signer.Initialize(keyPair);
    ///     bool valid = signer.Verify(data, 0, data.Length, code);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    ///     <revision date="2015/06/07" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE.RLWEPublicKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE RLWEPublicKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE.RLWEPrivateKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE RLWEPrivateKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKeyPair Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKey Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digests">VTDev.Libraries.CEXEngine.Crypto Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Signing is intended as a one time only key implementation (OTS); keys should never be re-used.</description></item>
    /// <item><description>Digests can be any of the implemented digests; Blake, Keccak, SHA-2 or Skein.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Ring-LWE-Encryption C version: <see href="https://github.com/ruandc/Ring-LWE-Encryption">ruandc/Ring-LWE-Encryption</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class RLWESign : IDisposable
    {
        #region Fields
        private IDigest _dgtEngine;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private IAsymmetricKeyPair _keyPair;
        private RLWEEncrypt _asyCipher;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        /// 
        /// <exception cref="RLWEException">Thrown if cipher has not been initialized</exception>
        public int MaxPlainText
        {
            get 
            { 
                if (!_isInitialized)
                    throw new RLWEException("RLWESign:MaxPlainText", "The signer has not been initialized!", new InvalidOperationException());

                if (_keyPair.PublicKey != null)
                    return ((RLWEPublicKey)_keyPair.PublicKey).N >> 3; 
                else
                    return ((RLWEPrivateKey)_keyPair.PrivateKey).N >> 3; 
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CipherParams">The RLWE cipher used to encrypt the hash</param>
        /// <param name="Digest">The type of digest engine used</param>
        public RLWESign(RLWEParameters CipherParams, Digests Digest = Digests.SHA512)
        {
            _asyCipher = new RLWEEncrypt(CipherParams);
            _dgtEngine = GetDigest(Digest);
        }

        private RLWESign()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWESign()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the cipher
        /// </summary>
        /// 
        /// <param name="KeyPair">The <see cref="IAsymmetricKeyPair"/> containing the RLWE public or private key</param>
        /// 
        /// <exception cref="RLWEException">Thrown if an invalid key pair is used</exception>
        public void Initialize(IAsymmetricKeyPair KeyPair)
        {
            if (!(KeyPair is RLWEKeyPair))
                throw new RLWEException("RLWESign:Initialize", "The key pair is not a valid RLWE key pair!", new InvalidDataException());

            Reset();
            _keyPair = KeyPair;
            _isInitialized = true;
        }

        /// <summary>
        /// Reset the underlying digest engine
        /// </summary>
        public void Reset()
        {
            _dgtEngine.Reset();
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The stream contining the data</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        /// 
        /// <exception cref="RLWEException">Thrown if an invalid key pair is used, or signer has not been initialized</exception>
        public byte[] Sign(Stream InputStream)
        {
            if (!_isInitialized)
                throw new RLWEException("RLWESign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (_keyPair.PublicKey == null)
                throw new RLWEException("RLWESign:Sign", "The public key is invalid!", new InvalidDataException());
            if (!(_keyPair.PublicKey is RLWEPublicKey))
                throw new RLWEException("RLWESign:Sign", "The public key is invalid!", new InvalidDataException());

            _asyCipher.Initialize(true, _keyPair);

            if (_asyCipher.MaxPlainText < _dgtEngine.DigestSize)
                throw new RLWEException("RLWESign:Sign", String.Format("The key size is too small; key supports encrypting up to {0} bytes!", _asyCipher.MaxPlainText), new ArgumentException());

            byte[] hash = Compute(InputStream);

            return _asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="Input">The byte array contining the data</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        /// 
        /// <exception cref="RLWEException">Thrown if input array is too short, signer is not initialized, or keys are invalid</exception>
        public byte[] Sign(byte[] Input, int Offset, int Length)
        {
            if (Input.Length - Offset < Length)
                throw new RLWEException("RLWESign:Sign", "The input array is too short!", new ArgumentException());
            if (!_isInitialized)
                throw new RLWEException("RLWESign:Sign", "The signer has not been initialized!", new InvalidOperationException());
            if (_keyPair.PublicKey == null)
                throw new RLWEException("RLWESign:Sign", "The public key is invalid!", new InvalidDataException());
            if (!(_keyPair.PublicKey is RLWEPublicKey))
                throw new RLWEException("RLWESign:Sign", "The public key is invalid!", new InvalidDataException());

            _asyCipher.Initialize(true, _keyPair);

            if (_asyCipher.MaxPlainText < _dgtEngine.DigestSize)
                throw new RLWEException("RLWESign:Sign", String.Format("The key size is too small; key supports encrypting up to {0} bytes!", _asyCipher.MaxPlainText), new InvalidDataException());

            byte[] hash = Compute(Input, Offset, Length);

            return _asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data to test</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        /// 
        /// <exception cref="RLWEException">Thrown if signer is not initialized, or keys are invalid</exception>
        public bool Verify(Stream InputStream, byte[] Code)
        {
            if (!_isInitialized)
                throw new RLWEException("RLWESign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (_keyPair.PrivateKey == null)
                throw new RLWEException("RLWESign:Verify", "The private key is invalid!", new InvalidDataException());
            if (!(_keyPair.PrivateKey is RLWEPrivateKey))
                throw new RLWEException("RLWESign:Verify", "The private key is invalid!", new InvalidDataException());

            _asyCipher.Initialize(false, _keyPair);
            byte[] chksum = _asyCipher.Decrypt(Code);
            byte[] hash = Compute(InputStream);

            return Compare.AreEqual(hash, chksum);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="Input">The stream containing the data to test</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        /// 
        /// <exception cref="RLWEException">Thrown if input array is too short, signer is not initialized, or keys are invalid</exception>
        public bool Verify(byte[] Input, int Offset, int Length, byte[] Code)
        {
            if (Input.Length - Offset < Length)
                throw new RLWEException("RLWESign:Verify", "The input array is too short!", new ArgumentOutOfRangeException());
            if (!_isInitialized)
                throw new RLWEException("RLWESign:Verify", "The signer has not been initialized!", new InvalidOperationException());
            if (_keyPair.PrivateKey == null)
                throw new RLWEException("RLWESign:Verify", "The private key is invalid!", new InvalidDataException());
            if (!(_keyPair.PrivateKey is RLWEPrivateKey))
                throw new RLWEException("RLWESign:Verify", "The private key is invalid!", new InvalidDataException());

            _asyCipher.Initialize(false, _keyPair);
            byte[] chksum = _asyCipher.Decrypt(Code);
            byte[] hash = Compute(Input, Offset, Length);

            return Compare.AreEqual(hash, chksum);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Compute the hash from a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The input stream</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(Stream InputStream)
        {
            int length = (int)(InputStream.Length - InputStream.Position);
            int blockSize = _dgtEngine.BlockSize < length ? length : _dgtEngine.BlockSize;
            int bytesRead = 0;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                bytesRead = InputStream.Read(buffer, 0, blockSize);
                _dgtEngine.BlockUpdate(buffer, 0, bytesRead);
                bytesTotal += bytesRead;
            }

            // last block
            if (bytesTotal < length)
            {
                buffer = new byte[length - bytesTotal];
                bytesRead = InputStream.Read(buffer, 0, buffer.Length);
                _dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
                bytesTotal += buffer.Length;
            }

            byte[] hash = new byte[_dgtEngine.DigestSize];
            _dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Compute the hash from a byte array
        /// </summary>
        /// 
        /// <param name="Input">The data byte array</param>
        /// <param name="Offset">The starting offset within the array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(byte[] Input, int Offset, int Length)
        {
            if (Length < Input.Length - Offset)
                throw new ArgumentOutOfRangeException();

            int blockSize = _dgtEngine.BlockSize < Length ? Length : _dgtEngine.BlockSize;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = Length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, blockSize);
                _dgtEngine.BlockUpdate(buffer, 0, blockSize);
                bytesTotal += blockSize;
            }

            // last block
            if (bytesTotal < Length)
            {
                buffer = new byte[Length - bytesTotal];
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, Math.Min(buffer.Length, Input.Length - bytesTotal));
                _dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
            }

            byte[] hash = new byte[_dgtEngine.DigestSize];
            _dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="Engine">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests Engine)
        {
            switch (Engine)
            {
                case Digests.Blake256:
                    return new Blake256();
                case Digests.Blake512:
                    return new Blake512();
                case Digests.Keccak256:
                    return new Keccak256();
                case Digests.Keccak512:
                    return new Keccak512();
                case Digests.SHA256:
                    return new SHA256();
                case Digests.SHA512:
                    return new SHA512();
                case Digests.Skein256:
                    return new Skein256();
                case Digests.Skein512:
                    return new Skein512();
                default:
                    throw new RLWEException("RLWESign:GetDigest", "The digest type is not unsupported!", new ArgumentException());
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_dgtEngine != null)
                    {
                        _dgtEngine.Dispose();
                        _dgtEngine = null;
                    }
                    if (_asyCipher != null)
                    {
                        _asyCipher.Dispose();
                        _asyCipher = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
