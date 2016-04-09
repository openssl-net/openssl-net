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
            /* Cipher context to use */                                                                             
            public EVP_CIPHER_CTX cctx;                                                                                    
            /* Keys k1 and k2 */                                                                                    
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] k1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] k2;
            /* Temporary block */                                                                                  
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] tbl;
            /* Last (possibly partial) block */                                                                   
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
            public byte[] last_block;
            /* Number of bytes in last block: -1 means context not initialised */                                
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
            ptr = Native.CMAC_CTX_new();
        }
        #endregion

        #region Methods

		/// <summary>
		/// Calls CMAC_Init()
		/// </summary>
		/// <param name="key"></param>
		public void Init(byte[] key) {
			if (key.Length != 16) {
				throw new Exception("Using key-size which isn't implemented: " + key.Length);
			}
			Cipher cipher = Cipher.AES_128_CBC;
			Native.CMAC_Init(ptr, key, key.Length, cipher.Handle, IntPtr.Zero);
			initialized = true;
			cmac_size = key.Length;
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
        /// Calls CMAC_Final()
        /// </summary>
        /// <returns></returns>
        public byte[] Final() {
            if (!initialized) {
                throw new Exception("Failed to call Initialize before calling DigestFinal");
            }


            var mac_value = new byte[cmac_size];
            uint mac_value_length = (uint) cmac_size;

            Native.CMAC_Final(ptr, mac_value, ref mac_value_length);
            return mac_value;
        }

        #endregion

        #region Overrides
        /// <summary>
        /// Calls CMAC_CTX_cleanup() and then OPENSSL_free()
        /// </summary>
        protected override void OnDispose() {
            // Clean up the context
            Native.CMAC_CTX_free(ptr);
        }
        #endregion

        #region Fields
        private bool initialized = false;
        private int cmac_size = 0;
        #endregion
    }
}