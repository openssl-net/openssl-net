using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
    public class PKCS12 : Base, IDisposable
    {
        #region PKCS12 structure

        [StructLayout(LayoutKind.Sequential)]
        struct _PKCS12
        {
            IntPtr version;     //ASN1_INTEGER *version;
            IntPtr mac;         //PKCS12_MAC_DATA *mac;
            IntPtr authsafes;   //PKCS7 *authsafes;
        }
        #endregion

        private CryptoKey privateKey;
        private X509Certificate certificate;
        private Stack<X509Certificate> caCertificates;
        private bool shouldDisposePrivateKey = true;
        private bool shouldDisposeCertificate = true;
        private bool shouldDisposeCACertificates = true;

        public PKCS12(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        {
        }

        public PKCS12(BIO bio, string password)
            : base(IntPtr.Zero, false)
        {
            IntPtr cert;
            IntPtr pkey;
            IntPtr cacerts;

            IntPtr ptr = Native.ExpectNonNull(Native.d2i_PKCS12_bio(bio.Handle, IntPtr.Zero));
            // set the base ptr
            this.ptr = ptr;
            this.owner = true;
            // Parse the PKCS12 object and get privatekey, cert, cacerts if available
            Native.ExpectSuccess(Native.PKCS12_parse(this.ptr, password, out pkey, out cert, out cacerts));
            if (pkey != IntPtr.Zero)
            {
                privateKey = new CryptoKey(pkey, true);
            }
            if (cert != IntPtr.Zero)
            {
                certificate = new X509Certificate(cert, true);
                if (privateKey != null)
                {
                    // We have a private key, assign it to the cert
                    privateKey.Addref();
                    CryptoKey key = new CryptoKey(privateKey.Handle, true);
                    certificate.PrivateKey = key;
                }
            }
            if (cacerts != IntPtr.Zero)
            {
                caCertificates = new Stack<X509Certificate>(cacerts, true);
            }
        }

        public X509Certificate Certificate
        {
            get
            {
                if (certificate != null)
                {
                    certificate.Addref();                    
                    X509Certificate cert = new X509Certificate(certificate.Handle, true);
                    if (privateKey != null)
                    {
                        privateKey.Addref();
                        CryptoKey key = new CryptoKey(privateKey.Handle, true);
                        cert.PrivateKey = key;
                    }
                    return cert;
                }
                return null;
            }
        }

        public CryptoKey PrivateKey
        {
            get
            {
                if (privateKey != null)
                {
                    privateKey.Addref();
                    CryptoKey key = new CryptoKey(privateKey.Handle, true);
                    return key;
                }
                return null;
            }
        }

        public Stack<X509Certificate> CACertificates
        {
            get
            {
                shouldDisposeCACertificates = false;
                return caCertificates;
            }
        }

        public override void OnDispose()
        {
            if (certificate != null)
            {
                certificate.Dispose();
            }
            if (privateKey != null)
            {
                privateKey.Dispose();
            }
            if (caCertificates != null)
            {
                caCertificates.Dispose();
            }
            Native.PKCS12_free(this.ptr);
        }
    }
}
