// Copyright (c) 2016 Bill Hass
// All rights reserved.
//
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

using OpenSSL.Core;
using OpenSSL.Crypto;
using System;
using System.Runtime.InteropServices;

namespace OpenSSL.Crypto {
    /// <summary>
    /// Wraps CMAC
    /// </summary>
    public class CMAC : Base {
        #region Raw Structures
        [StructLayout(LayoutKind.Sequential)]
        struct CMAC_CTX {
            /* Cipher context to use */                                                                             |
            public EVP_CIPHER_CTX cctx;                                                                                    |# define HMAC_size(e)    (EVP_MD_size((e)->md))
            /* Keys k1 and k2 */                                                                                    |
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] k1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] k2;
            /* Temporary block */                                                                                   |
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] tbl;
            /* Last (possibly partial) block */                                                                     |# define HMAC_cleanup(ctx) HMAC_CTX_cleanup(ctx)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] last_block;
            /* Number of bytes in last block: -1 means context not initialised */                                   |/* deprecated */
            int nlast_block;
        }
        #endregion

        #region Initialization
        /// <summary>
        /// Calls OPENSSL_malloc() and then CMAC_CTX_init()
        /// </summary>
        public CMAC()
            : base(IntPtr.Zero, true) {
            // Allocate the context
            ptr = Native.OPENSSL_malloc(Marshal.SizeOf(typeof(CMAC_CTX)));

            // Initialize the context
            Native.CMAC_CTX_init(ptr);
        }
        #endregion

        #region Methods

        /// <summary>
        /// Calls CMAC()
        /// </summary>
        /// <param name="digest"></param>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] Digest(MessageDigest digest, byte[] key, byte[] data) {
            var hash_value = new byte[digest.Size];
            uint hash_value_length = Native.EVP_MAX_MD_SIZE;
            Native.CMAC(digest.Handle, key, key.Length, data, data.Length, hash_value, ref hash_value_length);

            return hash_value;
        }

        /// <summary>
        /// Calls CMAC_Init_ex()
        /// </summary>
        /// <param name="key"></param>
        /// <param name="digest"></param>
        public void Init(byte[] key, MessageDigest digest) {
            Native.CMAC_Init_ex(ptr, key, key.Length, digest.Handle, IntPtr.Zero);
            digest_size = digest.Size;
            initialized = true;
        }

        /// <summary>
        /// Calls CMAC_Update()
        /// </summary>
        /// <param name="data"></param>
        public void Update(byte[] data) {
            if (!initialized) {
                throw new Exception("Failed to call Initialize before calling Update");
            }

            Native.CMAC_Update(ptr, data, data.Length);
        }

        /// <summary>
        /// Calls CMAC_Update()
        /// </summary>
        /// <param name="data"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        public void Update(byte[] data, int offset, int count) {
            if (!initialized) {
                throw new Exception("Failed to call Initialize before calling Update");
            }
            if (data == null) {
                throw new ArgumentNullException("data");
            }
            if (count <= 0) {
                throw new ArgumentException("count must be greater than 0");
            }
            if (offset < 0) {
                throw new ArgumentException("offset must be 0 or greater");
            }
            if (data.Length < (count - offset)) {
                throw new ArgumentException("invalid length specified.  Count is greater than buffer length.");
            }

            var seg = new ArraySegment<byte>(data, offset, count);
            Native.CMAC_Update(ptr, seg.Array, seg.Count);
        }

        /// <summary>
        /// Calls CMAC_Final()
        /// </summary>
        /// <returns></returns>
        public byte[] DigestFinal() {
            if (!initialized) {
                throw new Exception("Failed to call Initialize before calling DigestFinal");
            }

            var hash_value = new byte[digest_size];
            uint hash_value_length = Native.EVP_MAX_MD_SIZE;

            Native.CMAC_Final(ptr, hash_value, ref hash_value_length);
            return hash_value;
        }

        #endregion

        #region Overrides
        /// <summary>
        /// Calls CMAC_CTX_cleanup() and then OPENSSL_free()
        /// </summary>
        protected override void OnDispose() {
            // Clean up the context
            Native.CMAC_CTX_cleanup(ptr);

            // Free the structure allocation
            Native.OPENSSL_free(ptr);
        }
        #endregion

        #region Fields
        private bool initialized = false;
        private int digest_size = 0;
        #endregion
    }
}