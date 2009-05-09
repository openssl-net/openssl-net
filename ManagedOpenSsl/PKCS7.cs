using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
    public class PKCS7 : Base, IDisposable
    {
        #region PKCS7 structures
        public const int NID_pkcs7_signed = 22; // from obj_mac.h
        public const int NID_pkcs7_signedAndEnveloped = 24; // from obj_mac.h

        // State definitions
        public const int PKCS7_S_HEADER	= 0;
        public const int PKCS7_S_BODY	= 1;
        public const int PKCS7_S_TAIL	= 2;

        [StructLayout(LayoutKind.Explicit)]
        private struct _PKCS7
        {
	    /* The following is non NULL if it contains ASN1 encoding of
	     * this structure */
            [FieldOffset(0)]
	        public IntPtr asn1;    //unsigned char *asn1;
	        [FieldOffset(4)]
            public int length;     //long length;
            [FieldOffset(8)]
            public int state;      /* used during processing */
            [FieldOffset(12)]
            public int detached;
            [FieldOffset(16)]
            public IntPtr type;    //ASN1_OBJECT *type;
	    /* content as defined by the type */
	    /* all encryption/message digests are applied to the 'contents',
	     * leaving out the 'type' field. */
	    //union	{
		    [FieldOffset(20)]
            public IntPtr ptr;     //char *ptr;
            [FieldOffset(20)]
		    /* NID_pkcs7_data */
            public IntPtr data;    //ASN1_OCTET_STRING *data;
            [FieldOffset(20)]
		    /* NID_pkcs7_signed */
            public IntPtr sign;    //PKCS7_SIGNED *sign;
            [FieldOffset(20)]
		    /* NID_pkcs7_enveloped */
            public IntPtr enveloped;   //PKCS7_ENVELOPE *enveloped;
            [FieldOffset(20)]
		    /* NID_pkcs7_signedAndEnveloped */
            public IntPtr signed_and_enveloped;    //PKCS7_SIGN_ENVELOPE *signed_and_enveloped;
            [FieldOffset(20)]
		    /* NID_pkcs7_digest */
            public IntPtr digest;      //PKCS7_DIGEST *digest;
            [FieldOffset(20)]
		    /* NID_pkcs7_encrypted */
            public IntPtr encrypted;   //PKCS7_ENCRYPT *encrypted;
            [FieldOffset(20)]
		    /* Anything else */
            public IntPtr other;       //ASN1_TYPE *other;
		    //} d;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PKCS7_SIGNED
        {
	        public IntPtr version;      //ASN1_INTEGER			*version;	/* version 1 */
	        public IntPtr md_algs;      //STACK_OF(X509_ALGOR)		*md_algs;	/* md used */
	        public IntPtr cert;         //STACK_OF(X509)			*cert;		/* [ 0 ] */
	        public IntPtr crl;          //STACK_OF(X509_CRL)		*crl;		/* [ 1 ] */
	        public IntPtr signer_info;  //STACK_OF(PKCS7_SIGNER_INFO)	*signer_info;
            public IntPtr contents;     //struct pkcs7_st			*contents;
	    }

        [StructLayout(LayoutKind.Sequential)]
        private struct PKCS7_SIGN_ENVELOPE
        {
	        public IntPtr version;          //ASN1_INTEGER			*version;	/* version 1 */
	        public IntPtr md_algs;          //STACK_OF(X509_ALGOR)		*md_algs;	/* md used */
	        public IntPtr cert;             //STACK_OF(X509)			*cert;		/* [ 0 ] */
	        public IntPtr crl;              //STACK_OF(X509_CRL)		*crl;		/* [ 1 ] */
	        public IntPtr signer_info;      //STACK_OF(PKCS7_SIGNER_INFO)	*signer_info;
            public IntPtr enc_data;         //PKCS7_ENC_CONTENT		*enc_data;
	        public IntPtr recipientinfo;    //STACK_OF(PKCS7_RECIP_INFO)	*recipientinfo;
	    }

        #endregion

        private _PKCS7 raw;

        PKCS7(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        {
            raw = (_PKCS7)Marshal.PtrToStructure(ptr, typeof(_PKCS7));
        }

        static public PKCS7 FromASN1(BIO bio)
        {
            IntPtr ptr = Native.ExpectNonNull(Native.d2i_PKCS7_bio(bio.Handle, IntPtr.Zero));
            return new PKCS7(ptr, true);
        }

        static public PKCS7 FromPEM(BIO bio)
        {
            IntPtr ptr = Native.ExpectNonNull(Native.PEM_read_bio_PKCS7(bio.Handle, IntPtr.Zero, null, IntPtr.Zero));
            return new PKCS7(ptr, true);
        }

        public X509Chain Certificates
        {
            get
            {
                X509Chain chain = null;
                Stack<X509Certificate> cert_stack = null;
                int type = Native.OBJ_obj2nid(this.raw.type);
                switch (type)
                {
                    case NID_pkcs7_signed:
                        {
                            PKCS7_SIGNED signed = (PKCS7_SIGNED)Marshal.PtrToStructure(raw.sign, typeof(PKCS7_SIGNED));
                            cert_stack = new Stack<X509Certificate>(signed.cert, false);
                        }
                        break;
                    case NID_pkcs7_signedAndEnveloped:
                        {
                            PKCS7_SIGN_ENVELOPE envelope = (PKCS7_SIGN_ENVELOPE)Marshal.PtrToStructure(raw.signed_and_enveloped, typeof(PKCS7_SIGN_ENVELOPE));
                            cert_stack = new Stack<X509Certificate>(envelope.cert, false);
                        }
                        break;
                    default:
                        break;
                }
                if (cert_stack != null)
                {
                    chain = new X509Chain();
                    // We have a stack of certificates, build the chain object and return
                    foreach (X509Certificate cert in cert_stack)
                    {
                        chain.Add(cert);
                    }
                }
                return chain;
            }
        }

        public override void OnDispose()
        {
            Native.PKCS7_free(this.ptr);            
        }
        #region IDisposable Members

        void IDisposable.Dispose()
        {
            base.Dispose();
        }

        #endregion
    }
}
