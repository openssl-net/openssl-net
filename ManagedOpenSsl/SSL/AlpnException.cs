// Copyright © Microsoft Open Technologies, Inc.
// All Rights Reserved       

using System;

namespace OpenSSL.Exceptions
{
	/// <summary>
	/// Alpn exception.
	/// </summary>
    public class AlpnException : Exception
    {
		/// <summary>
		/// Initializes a new instance of the <see cref="OpenSSL.Exceptions.AlpnException"/> class.
		/// </summary>
		/// <param name="msg">Message.</param>
        public AlpnException(string msg)
            : base(msg)
        {
        }
    }
}