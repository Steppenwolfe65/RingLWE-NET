﻿#region Directives
using System;
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
    /// A Ring-LWE public key
    /// </summary>
    public class RLWEPublicKey : IAsymmetricKey
    {
        #region Fields
        private bool _isDisposed = false;
        // the length of the code
        private byte[] _A;
        // the error correction capability of the code
        private byte[] _P;
        // the number of coefficients
        private int _N;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the A array
        /// </summary>
        public byte[] A
        {
            get { return _A; }
        }

        /// <summary>
        /// Get: Returns the number of coefficients
        /// </summary>
        public int N
        {
            get { return _N; }
        }

        /// <summary>
        /// Get: Returns the P array
        /// </summary>
        public byte[] P
        {
            get { return _P; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="N">The number of coefficients</param>
        /// <param name="A">The polynomial 'a'</param>
        /// <param name="P">The polynomial 'p'</param>
        public RLWEPublicKey(int N, byte[] A, byte[] P)
        {
            _N = N;
            _A = A;
            _P = P;
        }
        
        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="MPKCException">Thrown if the key could not be loaded</exception>
        public RLWEPublicKey(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                int len = 0;
                // num coeffs
                _N = reader.ReadInt32();
                // a poly
                len = reader.ReadInt32();
                _A = reader.ReadBytes(len);
                // p poly
                len = reader.ReadInt32();
                _P = reader.ReadBytes(len);
            }
            catch (IOException ex)
            {
                throw new RLWEException("RLWEPublicKey:CTor", "The Public key could not be loaded!", ex);
            }
        }
        
        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="Key">The encoded key array</param>
        public RLWEPublicKey(byte[] Key) :
            this(new MemoryStream(Key))
        {
        }

        private RLWEPublicKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWEPublicKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a Public key from a byte array.
        /// <para>The array can contain only the public key.</para>
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the key</param>
        /// 
        /// <returns>An initialized RLWEPublicKey class</returns>
        public static RLWEPublicKey From(byte[] KeyArray)
        {
            return From(new MemoryStream(KeyArray));
        }

        /// <summary>
        /// Read a Public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the key</param>
        /// 
        /// <returns>An initialized RLWEPublicKey class</returns>
        /// 
        /// <exception cref="RLWEException">Thrown if the stream can not be read</exception>
        public static RLWEPublicKey From(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                int len = 0;
                // num coeffs
                int n = reader.ReadInt32();
                // a poly
                len = reader.ReadInt32();
                byte[] a = reader.ReadBytes(len);
                // p poly
                len = reader.ReadInt32();
                byte[] p = reader.ReadBytes(len);

                return new RLWEPublicKey(n, a, p);
            }
            catch (Exception ex)
            {
                throw new RLWEException("RLWEPrivateKey:Ctor", ex.Message, ex);
            }
        }

        /// <summary>
        /// Converts the key pair to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded key pair</returns>
        public byte[] ToBytes()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            // num coeff
            writer.Write(N);
            // write 'a' poly
            writer.Write(_A.Length);
            writer.Write(_A);
            // write 'p' poly
            writer.Write(_P.Length);
            writer.Write(_P);

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Returns the current key pair set as a MemoryStream
        /// </summary>
        /// 
        /// <returns>KeyPair as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            return new MemoryStream(ToBytes());
        }

        /// <summary>
        /// Writes the key pair to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">KeyPair as a byte array; can be initialized as zero bytes</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the key pair to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">KeyPair as a byte array; can be initialized as zero bytes</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="RLWEException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new RLWEException("RLWEPublicKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the key pair to an output stream
        /// </summary>
        /// 
        /// <param name="Output">Output Stream</param>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (IOException e)
            {
                throw new RLWEException(e.Message);
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Decides whether the given object <c>other</c> is the same as this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns <c>(this == other)</c></returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is RLWEPublicKey))
                return false;

            RLWEPublicKey key = (RLWEPublicKey)Obj;

            if (!N.Equals(key.N))
                return false;

            for (int i = 0; i < A.Length; i++)
            {
                if (key.A[i] != A[i])
                    return false;
            }
            for (int i = 0; i < P.Length; i++)
            {
                if (key.P[i] != P[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int code = N * 31;
            code += A.GetHashCode() * 31;
            code += P.GetHashCode() * 31;

            return code;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a copy of this RLWEPublicKey instance
        /// </summary>
        /// 
        /// <returns>RLWEPublicKey copy</returns>
        public object Clone()
        {
            return new RLWEPublicKey(_N, _A, _P);
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
                    if (_A != null)
                    {
                        Array.Clear(_A, 0, _A.Length);
                        _A = null;
                    }
                    if (_P != null)
                    {
                        Array.Clear(_P, 0, _P.Length);
                        _P = null;
                    }
                    _N = 0;
                    
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
