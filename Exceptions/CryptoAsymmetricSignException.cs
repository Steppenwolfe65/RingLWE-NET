﻿#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Exceptions
{
    /// <summary>
    /// Wraps exceptions thrown within a Asymmetric Signing operational context.
    /// <para>This exception is used throughout the Asymmetric Sign domain.</para>
    /// </summary>
    public sealed class CryptoAsymmetricSignException : Exception
    {
        /// <summary>
        /// The origin of the exception in the format Class:Method
        /// </summary>
        public string Origin { get; set; }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Message">A custom message or error data</param>
        public CryptoAsymmetricSignException(String Message) :
            base(Message)
        {
        }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Message">A custom message or error data</param>
        /// <param name="InnerException">The underlying exception</param>
        public CryptoAsymmetricSignException(String Message, Exception InnerException) :
            base(Message, InnerException)
        {
        }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Origin">The origin of the exception</param>
        /// <param name="Message">A custom message or error data</param>
        public CryptoAsymmetricSignException(String Origin, String Message) :
            base(Message)
        {
            this.Origin = Origin;
        }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Origin">The origin of the exception</param>
        /// <param name="Message">A custom message or error data</param>
        /// <param name="InnerException">The underlying exception</param>
        public CryptoAsymmetricSignException(String Origin, String Message, Exception InnerException) :
            base(Message, InnerException)
        {
            this.Origin = Origin;
        }
    }
}
