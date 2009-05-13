// Copyright (c) 2006-2007 Frank Laub
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
    #region X509StoreContext
    /// <summary>
    /// Wraps the X509_STORE_CTX object
    /// </summary>
    public class X509StoreContext : IDisposable
    {
        #region X509_STORE_CONTEXT
        [StructLayout(LayoutKind.Sequential)]
        private struct X509_STORE_CONTEXT
        {
            public IntPtr ctx;
            public int current_method;
            public IntPtr cert;
            public IntPtr untrusted;
            public int purpose;
            public int trust;
#if PocketPC
            public uint check_time;
#else
            public long check_time;
#endif
            public uint flags;
            public IntPtr other_ctx;
            public IntPtr verify;
            public IntPtr verify_cb;
            public IntPtr get_issuer;
            public IntPtr check_issued;
            public IntPtr check_revocation;
            public IntPtr get_crl;
            public IntPtr check_crl;
            public IntPtr cert_crl;
            public IntPtr cleanup;
            public int depth;
            public int valid;
            public int last_untrusted;
            public IntPtr chain;
            public int error_depth;
            public int error;
            public IntPtr current_cert;
            public IntPtr current_issuer;
            public IntPtr current_crl;
            #region CRYPTO_EX_DATA ex_data;
            public IntPtr ex_data_sk;
            public int ex_data_dummy;
            #endregion
        }
        #endregion

        private IntPtr ptr;
        private bool own_ptr;

        public X509StoreContext()
        {
            this.ptr = Native.ExpectNonNull(Native.X509_STORE_CTX_new());
            own_ptr = true;
        }

        public X509StoreContext(IntPtr x509_store_ctx)
        {
            this.ptr = x509_store_ctx;
            own_ptr = false;
        }

        public X509Certificate CurrentCert
        {
            get
            {
                IntPtr cert = Native.X509_STORE_CTX_get_current_cert(this.ptr);
                return new X509Certificate(cert, false);
            }
        }

        public int ErrorDepth
        {
            get
            {
                return Native.X509_STORE_CTX_get_error_depth(this.ptr);
            }
        }

        public int Error
        {
            get
            {
                return Native.X509_STORE_CTX_get_error(this.ptr);
            }
            set
            {
                Native.X509_STORE_CTX_set_error(this.ptr, value);
            }
        }

        public X509Store Store
        {
            get
            {
                X509_STORE_CONTEXT ctx = Raw;
                X509Store store = new X509Store(ctx.ctx, false);
                return store;
            }
        }

        public void init(X509Store store, X509Certificate cert, X509Chain uchain)
        {
            Native.ExpectSuccess(Native.X509_STORE_CTX_init(
                this.ptr,
                store.Handle,
                cert != null ? cert.Handle : IntPtr.Zero,
                uchain.Handle));
        }

        public bool verify()
        {
            int ret = Native.X509_verify_cert(this.ptr);
            if (ret < 0)
                throw new OpenSslException();
            return ret == 1;
        }

        private X509_STORE_CONTEXT Raw
        {
            get
            {
                return (X509_STORE_CONTEXT)Marshal.PtrToStructure(this.ptr, typeof(X509_STORE_CONTEXT));
            }
        }

        public string ErrorString
        {
            get
            {
                return Native.PtrToStringAnsi(Native.X509_verify_cert_error_string(this.Raw.error), false);
            }
        }

        #region IDisposable Members
        public void Dispose()
        {
            if (own_ptr)
            {
                Native.X509_STORE_CTX_free(this.ptr);
            }
        }
        #endregion
    }
    #endregion

    public class X509Object : Base, IDisposable, IStackable
    {
        public const int X509_LU_RETRY		= -1;
        public const int X509_LU_FAIL		= 0;
        public const int X509_LU_X509		= 1;
        public const int X509_LU_CRL		= 2;
        public const int X509_LU_PKEY		= 3;

        [StructLayout(LayoutKind.Explicit)]
        internal struct X509_OBJECT
	    {
	        /* one of the above types */
            [FieldOffset(0)]
            public int type;
	        [FieldOffset(4)]
		    public IntPtr ptr;     //char *ptr;
		    [FieldOffset(4)]
            public IntPtr x509;    //X509 *x509;
		    [FieldOffset(4)]
		    public IntPtr crl;     //X509_CRL *crl;
		    [FieldOffset(4)]
            public IntPtr pkey;    //EVP_PKEY *pkey;
	    }

        private X509_OBJECT raw;

        public X509Object()
            : base(IntPtr.Zero, false)
        {
        }

        public X509Object(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        {
            raw = (X509_OBJECT)Marshal.PtrToStructure(this.ptr, typeof(X509_OBJECT)); 
        }

        public int Type
        {
            get
            {
                return raw.type;
            }
        }

        public X509Certificate Certificate
        {
            get
            {
                X509Certificate cert = null;
                if (raw.type == X509_LU_X509)
                {
                    cert = new X509Certificate(raw.x509, false);
                }
                return cert;
            }
        }

        public CryptoKey PrivateKey
        {
            get
            {
                CryptoKey key = null;
                if (raw.type == X509_LU_PKEY)
                {
                    key = new CryptoKey(raw.pkey, false);
                }
                return key;
            }
        }

        //!! TODO - Add support for CRL

        public override void  OnDispose()
        {
 	         //!! TODO
        }

        #region IStackable Members

        public override IntPtr Handle
        {
            get
            {
                return base.Handle;
            }
            set
            {
                base.Handle = value;
                // Marshal the structure when the handle is set on the object (most likely in a stack)
                raw = (X509_OBJECT)Marshal.PtrToStructure(this.ptr, typeof(X509_OBJECT)); 
            }
        }

        #endregion
    }

    /// <summary>
	/// Wraps the X509_STORE_CONTEXT object
	/// </summary>
	public class X509Store : Base, IDisposable
	{
        [StructLayout(LayoutKind.Sequential)]
        public struct X509_STORE
	    {
	        /* The following is a cache of trusted certs */
	        public int cache; 	/* if true, stash any hits */
	        public IntPtr objs;    //STACK_OF(X509_OBJECT) *objs;	/* Cache of all objects */

	        /* These are external lookup methods */
	        public IntPtr get_cert_methods;    //STACK_OF(X509_LOOKUP) *get_cert_methods;

            IntPtr param;   // X509_VERIFY_PARAM* param;

	        /* Callbacks for various operations */
	        public IntPtr verify;  //int (*verify)(X509_STORE_CTX *ctx);	/* called to verify a certificate */
	        public IntPtr verify_cb;   //int (*verify_cb)(int ok,X509_STORE_CTX *ctx);	/* error callback */
	        public IntPtr get_issuer;  //int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);	/* get issuers cert from ctx */
	        public IntPtr check_issued;    //int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer); /* check issued */
	        public IntPtr check_revocation;    //int (*check_revocation)(X509_STORE_CTX *ctx); /* Check revocation status of chain */
	        public IntPtr get_crl; //int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x); /* retrieve CRL */
	        public IntPtr check_crl;   //int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl); /* Check CRL validity */
	        public IntPtr cert_crl;    //int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x); /* Check certificate against CRL */
	        public IntPtr cleanup; //int (*cleanup)(X509_STORE_CTX *ctx);
            #region CRYPTO_EX_DATA ex_data;
            public IntPtr ex_data_sk;
            public int ex_data_dummy;
            #endregion
	        public int references;
	    }

        private List<X509Certificate> internalList = new List<X509Certificate>();
        private X509Chain untrusted = new X509Chain();
		//private X509Chain trusted = new X509Chain();

		/// <summary>
		/// Calls X509_STORE_new()
		/// </summary>
		public X509Store() : base(Native.ExpectNonNull(Native.X509_STORE_new()), true) {}

        /// <summary>
        /// Initializes the X509Store object with a pre-existing native X509_STORE pointer
        /// </summary>
        /// <param name="ptr"></param>
        /// <param name="takeOwnership"></param>
        public X509Store(IntPtr ptr, bool takeOwnership) :
            base(ptr, takeOwnership)
        {
        }

        /// <summary>
        /// Calls X509_STORE_new() and then adds the specified chain as trusted.
        /// </summary>
        /// <param name="chain"></param>
        public X509Store(X509Chain chain)
            : this(chain, true)
        {
        }

        /// <summary>
        /// Calls X509_STORE_new() and then adds the specified chaing as trusted.
        /// </summary>
        /// <param name="chain"></param>
        /// <param name="takeOwnership"></param>
        public X509Store(X509Chain chain, bool takeOwnership)
            : base(Native.ExpectNonNull(Native.X509_STORE_new()), takeOwnership)
        {
            foreach (X509Certificate cert in chain)
            {
                this.AddTrusted(cert);
            }
        }

        public override bool IsOwner
        {
            get
            {
                return base.IsOwner;
            }
            set
            {
                base.IsOwner = value;
            }
        }

        public override void Addref()
        {
            int offset = (int)Marshal.OffsetOf(typeof(X509_STORE), "references");
            IntPtr offset_ptr = new IntPtr((int)ptr + offset);
            Native.CRYPTO_add_lock(offset_ptr, 1, Native.CryptoLockTypes.CRYPTO_LOCK_X509_STORE, "X509Store.cs", 0);
        }

        private void PrintRefCount(string method)
        {
            int offset = (int)Marshal.OffsetOf(typeof(X509_STORE), "references");
            IntPtr offset_ptr = new IntPtr((int)ptr + offset);
            int ref_count = Marshal.ReadInt32(offset_ptr);
            Console.WriteLine("X509Store:method:{0}:ptr={1}:ref_count={2}", method, this.ptr, ref_count);
        }

        public Stack<X509Object> Objects
        {
            get
            {
                X509_STORE raw = (X509_STORE)Marshal.PtrToStructure(this.ptr, typeof(X509_STORE));
                Stack<X509Object> stack = new Stack<X509Object>(raw.objs, false);
                return stack;
            }
        }

        /// <summary>
		/// Returns the trusted state of the specified certificate
		/// </summary>
		/// <param name="cert"></param>
		/// <param name="error"></param>
		/// <returns></returns>
		public bool Verify(X509Certificate cert, out string error)
		{
            using (X509StoreContext ctx = new X509StoreContext())
            {
                ctx.init(this, cert, this.untrusted);
                if (ctx.verify())
                {
                    error = "";
                    return true;
                }
                error = ctx.ErrorString;
            }
            return false;
        }

		/// <summary>
		/// Adds a chain to the trusted list.
		/// </summary>
		/// <param name="chain"></param>
		public void AddTrusted(X509Chain chain)
		{
			foreach (X509Certificate cert in chain)
				AddTrusted(cert);
		}

		/// <summary>
		/// Adds a certificate to the trusted list.
		/// </summary>
		/// <param name="cert"></param>
		public void AddTrusted(X509Certificate cert)
		{
            // Don't Addref here -- X509_STORE_add_cert increases the refcount of the certificate pointer
            Native.ExpectSuccess(Native.X509_STORE_add_cert(this.ptr, cert.Handle));
		}

		/// <summary>
		/// Add an untrusted certificate
		/// </summary>
		/// <param name="cert"></param>
		public void AddUntrusted(X509Certificate cert)
		{
			this.untrusted.Add(cert);
		}

		//public X509Chain Trusted
		//{
		//    get { return this.trusted; }
		//    set { this.trusted = value; }
		//}

		/// <summary>
		/// Accessor to the untrusted list
		/// </summary>
		public X509Chain Untrusted
		{
			get { return this.untrusted; }
			set { this.untrusted = value; }
		}

		#region IDisposable Members
		/// <summary>
		/// Calls X509_STORE_free()
		/// </summary>
		public override void OnDispose()
		{
			Native.X509_STORE_free(this.ptr);
            if (this.untrusted != null)
            {
                this.untrusted.Dispose();
                this.untrusted = null;
            }
		}
		#endregion
	}
}
