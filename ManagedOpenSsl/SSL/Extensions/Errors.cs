// Copyright © Microsoft Open Technologies, Inc.
// All Rights Reserved       

namespace OpenSSL.SSL
{
    internal enum Errors : int
    {
        SSL_TLSEXT_ERR_OK = 0,
        SSL_TLSEXT_ERR_ALERT_WARNING = 1,
        SSL_TLSEXT_ERR_ALERT_FATAL = 2,
        SSL_TLSEXT_ERR_NOACK = 3,
    }
}
