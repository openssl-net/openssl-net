// Copyright (c) 2009 Ben Henderson
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
    [StructLayout(LayoutKind.Sequential)]
    public struct EVP_MD_CTX
	{
	    IntPtr digest;      //const EVP_MD *digest;
	    IntPtr engine;      //ENGINE *engine; /* functional reference if 'digest' is ENGINE-provided */
	    uint flags;         //unsigned long flags;
	    IntPtr md_data;     //void *md_data;
	}
    
    [StructLayout(LayoutKind.Sequential)]
    public struct FIPS_HMAC_CTX
	{
	    public IntPtr md;          //const EVP_MD *md;
	    public EVP_MD_CTX md_ctx;
	    public EVP_MD_CTX i_ctx;
	    public EVP_MD_CTX o_ctx;
	    public uint key_length;    //unsigned int key_length;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=Native.FIPS_HMAC_MAX_MD_CBLOCK)]
	    public byte[] key;
	}

    [StructLayout(LayoutKind.Sequential)]
    public struct HMAC_CTX
	{
	    public IntPtr md;          //const EVP_MD *md;
	    public EVP_MD_CTX md_ctx;
	    public EVP_MD_CTX i_ctx;
	    public EVP_MD_CTX o_ctx;
	    public uint key_length;    //unsigned int key_length;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=Native.HMAC_MAX_MD_CBLOCK)]
	    public byte[] key;
	}

    class HMACContext : Base, IDisposable
    {
        public HMACContext()
            : base(IntPtr.Zero, false)
        {
            // Allocate the context
            if (FIPS.Enabled)
            {
                this.ptr = Native.OPENSSL_malloc(Marshal.SizeOf(typeof(FIPS_HMAC_CTX)));
            }
            else
            {
                this.ptr = Native.OPENSSL_malloc(Marshal.SizeOf(typeof(HMAC_CTX)));
            }
            this.owner = true;
            // Initialize the context
            Native.HMAC_CTX_init(this.ptr);
        }

		protected override void OnDispose() {
            // Clean up the context
            Native.HMAC_CTX_cleanup(this.ptr);
            // Free the structure allocation
            Native.OPENSSL_free(this.ptr);
        }
    }

    public class HMAC : IDisposable
    {
        private HMACContext hmac_context = null;
        private bool initialized = false;
        private int digest_size = 0;

        public HMAC()
        {
        }

        static public byte[] Digest(MessageDigest digest, byte[] key, byte[] data)
        {
            byte[] hash_value = new byte[digest.Size];
            uint hash_value_length = Native.EVP_MAX_MD_SIZE;
            Native.HMAC(digest.Handle, key, key.Length, data, data.Length, hash_value, ref hash_value_length);
            return hash_value;
        }

        public void Init(byte[] key, MessageDigest digest)
        {
            hmac_context = new HMACContext();
            Native.HMAC_Init_ex(hmac_context.Handle, key, key.Length, digest.Handle, IntPtr.Zero);
            digest_size = digest.Size;
            initialized = true;
        }

        public void Update(byte[] data)
        {
            if (! initialized)
            {
                throw new Exception("Failed to call Initialize before calling Update");
            }
            Native.HMAC_Update(hmac_context.Handle, data, data.Length);
        }

        public void Update(byte[] data, int offset, int count)
        {
            if (! initialized)
            {
                throw new Exception("Failed to call Initialize before calling Update");
            }
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }
            if (count <= 0)
            {
                throw new ArgumentException("count must be greater than 0");
            }
            if (offset < 0)
            {
                throw new ArgumentException("offset must be 0 or greater");
            }
            if (data.Length < (count - offset))
            {
                throw new ArgumentException("invalid length specified.  Count is greater than buffer length.");
            }
            ArraySegment<byte> seg = new ArraySegment<byte>(data, offset, count);
            Native.HMAC_Update(hmac_context.Handle, seg.Array, seg.Count);
        }

        public byte[] DigestFinal()
        {
            if (!initialized)
            {
                throw new Exception("Failed to call Initialize before calling DigestFinal");
            }
            byte[] hash_value = new byte[digest_size];
            uint hash_value_length = Native.EVP_MAX_MD_SIZE;
            
            Native.HMAC_Final(hmac_context.Handle, hash_value, ref hash_value_length);
            return hash_value;
        }

        #region IDisposable Members

        public void  Dispose()
        {
 	        if (hmac_context != null)
            {
                hmac_context.Dispose();
            }
        }

        #endregion
    }
}
