#region Directives
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
    /// Creates, reads and writes parameter settings for RLWEEncrypt.
    /// <para>Predefined parameter sets are available through the <see cref="RLWEParamSets"/> class</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create a parameter set and write to stream:</description>
    /// <code>
    /// MemoryStream ks = new MemoryStream();
    /// using (RLWEParameters mp = new RLWEParameters(512, 12289, 12.18, new byte[] { 2, 5, 1 }))
    ///    mp.WriteTo(ks);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/06/07" version="1.0.1.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE.RLWEEncrypt">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE RLWEEncrypt Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prngs">VTDev.Libraries.CEXEngine.Crypto.Prngs Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digests">VTDev.Libraries.CEXEngine.Crypto.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>RLWE Parameter Description:</h4></description>
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
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Ring-LWE-Encryption C version: <see href="https://github.com/ruandc/Ring-LWE-Encryption">version</see>.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class RLWEParameters : IAsymmetricParameters, ICloneable, IDisposable
    {
        #region Constants
        /// <summary>
        /// The default prepended message padding length
        /// </summary>
        private const int DEFAULT_MFP = 0;

        /// <summary>
        /// The default number of coefficients
        /// </summary>
        private const int DEFAULT_N = 512;

        /// <summary>
        /// The default modulus
        /// </summary>
        private const int DEFAULT_Q = 12289;

        /// <summary>
        /// The default sigma value
        /// </summary>
        private const double DEFAULT_SIGMA = 12.18;
        #endregion

        #region Fields
        private int _N;
        private int _Q;
        private double _Sigma;
        private int _mFp;
        private byte[] _oId = new byte[3];
        private bool _isDisposed = false;
        private Prngs _rndEngine = Prngs.CSPRng;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Three bytes that uniquely identify the parameter set
        /// </summary>
        public byte[] OId
        {
            get { return _oId; }
            private set
            {
                if (value == null)
                    throw new RLWEException("Oid can not be null!");
                if (value.Length != 3)
                    throw new RLWEException("Oid must be 3 bytes in length!");

                _oId = value;
            }
        }

        /// <summary>
        /// The number of random bytes to prepend to the message
        /// </summary>
        public int MFP
        {
            get { return _mFp; }
        }

        /// <summary>
        /// Returns the number of coefficients
        /// </summary>
        public int N
        {
            get { return _N; }
        }

        /// <summary>
        /// Return the modulus
        /// </summary>
        public int Q
        {
            get { return _Q; }
        }

        /// <summary>
        /// The random engine used by SecureRandom
        /// </summary>
        public Prngs RandomEngine
        {
            get { return _rndEngine; }
            private set {_rndEngine = value; }
        }

        /// <summary>
        /// Returns the sigma value
        /// </summary>
        public double Sigma
        {
            get { return _Sigma; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Set the default parameters (N:512, Q:12289, Sigma:12.18)
        /// </summary>
        /// 
        /// <param name="OId">Three bytes that uniquely identify the parameter set</param>
        /// <param name="Engine">The PRNG engine used to power SecureRandom</param>
        /// 
        /// <exception cref="System.ArgumentException">Thrown if <c>N</c> or <c>Q</c> are invalid</exception>
        public RLWEParameters(byte[] OId, Prngs Engine = Prngs.CSPRng) :
            this(DEFAULT_N, DEFAULT_Q, DEFAULT_SIGMA, OId)
        {
            this.RandomEngine = Engine;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="N">The number of coefficients</param>
        /// <param name="Q">The Q modulus</param>
        /// <param name="Sigma">The Sigma value</param>
        /// <param name="OId">Three bytes that uniquely identify the parameter set</param>
        /// <param name="MFP">The number of random bytes to prepend to the message</param>
        /// <param name="Engine">The PRNG engine used to power SecureRandom</param>
        /// 
        /// <exception cref="RLWEException">Thrown if <c>N</c> or <c>Q</c> are invalid</exception>
        public RLWEParameters(int N, int Q, double Sigma, byte[] OId, int MFP = DEFAULT_MFP, Prngs Engine = Prngs.CSPRng)
        {
            if (N != 256 && N != 512)
                throw new RLWEException("RLWEParameters:Ctor", "N is invalid (only 256 or 512 currently supported)!", new ArgumentOutOfRangeException());
            if (Q != 7681 && Q != 12289)
                throw new RLWEException("RLWEParameters:Ctor", "Q is invalid (only 7681 or 12289 currently supported)!", new ArgumentOutOfRangeException());
            if (Sigma != 11.31 && Sigma != 12.18)
                throw new RLWEException("RLWEParameters:Ctor", "Sigma is invalid (only 11.31 or 12.18 currently supported)!", new ArgumentOutOfRangeException());
            if (N == 256 && MFP > 16 || N == 512 && MFP > 32)
                throw new RLWEException("RLWEParameters:Ctor", "MFP is invalid (forward padding can not be longer than half the maximum message size)!", new ArgumentOutOfRangeException());

            _Sigma = Sigma;
            _N = N;
            _Q = Q;
            Array.Copy(OId, this.OId, Math.Min(OId.Length, 3));
            _mFp = MFP;
            _rndEngine = Engine;
        }

        private RLWEParameters()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RLWEParameters()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a Public key from a byte array.
        /// </summary>
        /// 
        /// <param name="ParamArray">The byte array containing the parameters</param>
        /// 
        /// <returns>An initialized RLWEParameters class</returns>
        public static RLWEParameters From(byte[] ParamArray)
        {
            return From(new MemoryStream(ParamArray));
        }

        /// <summary>
        /// Read a Parameters file from a byte array.
        /// </summary>
        /// 
        /// <param name="ParamStream">The byte array containing the params</param>
        /// 
        /// <returns>An initialized RLWEParameters class</returns>
        public static RLWEParameters From(Stream ParamStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(ParamStream);
                int n = reader.ReadInt32();
                int q = reader.ReadInt32();
                double s = reader.ReadDouble();
                byte[] oid = reader.ReadBytes(3);
                int mfp = reader.ReadInt32();
                Prngs eng = (Prngs)reader.ReadInt32();

                return new RLWEParameters(n, q, s, oid, mfp, eng);
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Returns the current parameter set as an ordered byte array
        /// </summary>
        /// 
        /// <returns>RLWEParameters as a byte array</returns>
        public byte[] ToBytes()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(_N);
            writer.Write(_Q);
            writer.Write(_Sigma);
            writer.Write(_oId);
            writer.Write(_mFp);
            writer.Write((int)_rndEngine);
            writer.Seek(0, SeekOrigin.Begin);

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Returns the current parameter set as a MemoryStream
        /// </summary>
        /// 
        /// <returns>RLWEParameters as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            return new MemoryStream(ToBytes());
        }

        /// <summary>
        /// Writes the parameter set to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">RLWEParameters as a byte array; can be initialized as zero bytes</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the parameter set to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">RLWEParameters as a byte array; array must be initialized and of sufficient length</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="RLWEException">Thrown if The output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new RLWEException("RLWEParameters:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the parameter set to an output stream
        /// </summary>
        /// 
        /// <param name="Output">Output stream</param>
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
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int result = 1;
            result += 31 * _N;
            result += 31 * _Q;
            result += 31 * _mFp;
            result += (int)Math.Round(31 * _Sigma);
            result += 31 * (int)_rndEngine;

            return result;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (this == Obj)
                return true;
            if (Obj == null && this != null)
                return false;

            RLWEParameters other = (RLWEParameters)Obj;

            if (_N != other.N)
                return false;
            if (_Q != other.Q)
                return false;
            if (_rndEngine != other.RandomEngine)
                return false;
            if (_Sigma != other.Sigma)
                return false;
            if (_mFp != other.MFP)
                return false;

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a copy of this RLWEParameters instance
        /// </summary>
        /// 
        /// <returns>RLWEParameters copy</returns>
        public object Clone()
        {
            return new RLWEParameters(_N, _Q, _Sigma, _oId, _mFp, _rndEngine);
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
                    _N = 0;
                    _Q = 0;
                    _Sigma = 0;
                    _mFp = 0;
                    _rndEngine = 0;
                    if (_oId != null)
                    {
                        Array.Clear(_oId, 0, _oId.Length);
                        _oId = null;
                    }
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
