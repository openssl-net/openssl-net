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
                    certificate.PrivateKey = privateKey;
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
                shouldDisposeCertificate = false;
                return certificate;
            }
        }

        public CryptoKey PrivateKey
        {
            get
            {
                shouldDisposePrivateKey = false;
                return privateKey;
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
            if (certificate != null && ! shouldDisposeCertificate)
            {
                certificate.Dispose();
            }
            if (privateKey != null && ! shouldDisposePrivateKey)
            {
                privateKey.Dispose();
            }
            if (caCertificates != null && ! shouldDisposeCACertificates)
            {
                caCertificates.Dispose();
            }
            Native.PKCS12_free(this.ptr);
        }
    }
}
