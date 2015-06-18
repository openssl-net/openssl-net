// Copyright © Microsoft Open Technologies, Inc.
// All Rights Reserved       

namespace OpenSSL
{
    /// <summary>
    /// see 12 -> 3.1.  HTTP/2 Version Identification
    /// </summary>
    public static class Protocols
    {
		/// <summary>
		/// The http2.
		/// </summary>
        public static string Http2 = "h2-12";
		/// <summary>
		/// The http2 no tls.
		/// </summary>
        public static string Http2NoTls = "h2c-12";
		/// <summary>
		/// The http1.
		/// </summary>
        public static string Http1 = "http/1.1";
    }
}
