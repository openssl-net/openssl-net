// Copyright © Microsoft Open Technologies, Inc.
// All Rights Reserved       

using System;

namespace ManagedOpenSsl.NetCore.SSL
{
	/// <summary>
	/// Alpn exception.
	/// </summary>
    public class AlpnException : Exception
    {
		/// <summary>
		/// Initializes a new instance of the <see cref="AlpnException"/> class.
		/// </summary>
		/// <param name="msg">Message.</param>
        public AlpnException(string msg)
            : base(msg)
        {
        }
    }
}