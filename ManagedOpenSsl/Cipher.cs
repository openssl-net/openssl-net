using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;

namespace OpenSSL
{
	#region Cipher
	public class Cipher : Base
	{
		private EVP_CIPHER raw;
		internal Cipher(IntPtr ptr) : base(ptr) 
		{
			this.raw = (EVP_CIPHER)Marshal.PtrToStructure(this.ptr, typeof(EVP_CIPHER));
		}

		public override void Print(BIO bio)
		{
			bio.Write(this.LongName);
		}

		#region EVP_CIPHER
		[StructLayout(LayoutKind.Sequential)]
		struct EVP_CIPHER
		{
			public int nid;
			public int block_size;
			public int key_len;
			public int iv_len;
			public uint flags;
			public IntPtr init;
			public IntPtr do_cipher;
			public IntPtr cleanup;
			public int ctx_size;
			public IntPtr set_asn1_parameters;
			public IntPtr get_asn1_parameters;
			public IntPtr ctrl;
			public IntPtr app_data;		
		}
		#endregion

		#region Ciphers
		public static Cipher Null = new Cipher(Native.EVP_enc_null());
		public static Cipher DES_ECB = new Cipher(Native.EVP_des_ecb());
		public static Cipher DES_EDE = new Cipher(Native.EVP_des_ede());
		public static Cipher DES_EDE3 = new Cipher(Native.EVP_des_ede3());
		public static Cipher DES_EDE_ECB = new Cipher(Native.EVP_des_ede_ecb());
		public static Cipher DES_EDE3_ECB = new Cipher(Native.EVP_des_ede3_ecb());
		public static Cipher DES_CFB64 = new Cipher(Native.EVP_des_cfb64());
		public static Cipher DES_CFB1 = new Cipher(Native.EVP_des_cfb1());
		public static Cipher DES_CFB8 = new Cipher(Native.EVP_des_cfb8());
		public static Cipher DES_EDE_CFB64 = new Cipher(Native.EVP_des_ede_cfb64());
		public static Cipher DES_EDE3_CFB64 = new Cipher(Native.EVP_des_ede3_cfb64());
		public static Cipher DES_EDE3_CFB1 = new Cipher(Native.EVP_des_ede3_cfb1());
		public static Cipher DES_EDE3_CFB8 = new Cipher(Native.EVP_des_ede3_cfb8());
		public static Cipher DES_OFB = new Cipher(Native.EVP_des_ofb());
		public static Cipher DES_EDE_OFB = new Cipher(Native.EVP_des_ede_ofb());
		public static Cipher DES_EDE3_OFB = new Cipher(Native.EVP_des_ede3_ofb());
		public static Cipher DES_CBC = new Cipher(Native.EVP_des_cbc());
		public static Cipher DES_EDE_CBC = new Cipher(Native.EVP_des_ede_cbc());
		public static Cipher DES_EDE3_CBC = new Cipher(Native.EVP_des_ede3_cbc());
		public static Cipher DESX_CBC = new Cipher(Native.EVP_desx_cbc());
		public static Cipher RC4 = new Cipher(Native.EVP_rc4());
		public static Cipher RC4_40 = new Cipher(Native.EVP_rc4_40());
		public static Cipher Idea_ECB = new Cipher(Native.EVP_idea_ecb());
		public static Cipher Idea_CFB64 = new Cipher(Native.EVP_idea_cfb64());
		public static Cipher Idea_OFB = new Cipher(Native.EVP_idea_ofb());
		public static Cipher Idea_CBC = new Cipher(Native.EVP_idea_cbc());
		public static Cipher RC2_ECB = new Cipher(Native.EVP_rc2_ecb());
		public static Cipher RC2_CBC = new Cipher(Native.EVP_rc2_cbc());
		public static Cipher RC2_40_CBC = new Cipher(Native.EVP_rc2_40_cbc());
		public static Cipher RC2_64_CBC = new Cipher(Native.EVP_rc2_64_cbc());
		public static Cipher RC2_CFB64 = new Cipher(Native.EVP_rc2_cfb64());
		public static Cipher RC2_OFB = new Cipher(Native.EVP_rc2_ofb());
		public static Cipher Blowfish_ECB = new Cipher(Native.EVP_bf_ecb());
		public static Cipher Blowfish_CBC = new Cipher(Native.EVP_bf_cbc());
		public static Cipher Blowfish_CFB64 = new Cipher(Native.EVP_bf_cfb64());
		public static Cipher Blowfish_OFB = new Cipher(Native.EVP_bf_ofb());
		public static Cipher Cast5_ECB = new Cipher(Native.EVP_cast5_ecb());
		public static Cipher Cast5_CBC = new Cipher(Native.EVP_cast5_cbc());
		public static Cipher Cast5_OFB64 = new Cipher(Native.EVP_cast5_cfb64());
		public static Cipher Cast5_OFB = new Cipher(Native.EVP_cast5_ofb());
		public static Cipher RC5_32_12_16_CBC = new Cipher(Native.EVP_rc5_32_12_16_cbc());
		public static Cipher RC5_32_12_16_ECB = new Cipher(Native.EVP_rc5_32_12_16_ecb());
		public static Cipher RC5_32_12_16_CFB64 = new Cipher(Native.EVP_rc5_32_12_16_cfb64());
		public static Cipher RC5_32_12_16_OFB = new Cipher(Native.EVP_rc5_32_12_16_ofb());
		public static Cipher AES_128_ECB = new Cipher(Native.EVP_aes_128_ecb());
		public static Cipher AES_128_CBC = new Cipher(Native.EVP_aes_128_cbc());
		public static Cipher AES_128_CFB1 = new Cipher(Native.EVP_aes_128_cfb1());
		public static Cipher AES_128_CFB8 = new Cipher(Native.EVP_aes_128_cfb8());
		public static Cipher AES_128_CFB128 = new Cipher(Native.EVP_aes_128_cfb128());
		public static Cipher AES_128_OFB = new Cipher(Native.EVP_aes_128_ofb());
		public static Cipher AES_192_ECB = new Cipher(Native.EVP_aes_192_ecb());
		public static Cipher AES_192_CBC = new Cipher(Native.EVP_aes_192_cbc());
		public static Cipher AES_192_CFB1 = new Cipher(Native.EVP_aes_192_cfb1());
		public static Cipher AES_192_CFB8 = new Cipher(Native.EVP_aes_192_cfb8());
		public static Cipher AES_192_CFB128 = new Cipher(Native.EVP_aes_192_cfb128());
		public static Cipher AES_192_OFB = new Cipher(Native.EVP_aes_192_ofb());
		public static Cipher AES_256_ECB = new Cipher(Native.EVP_aes_256_ecb());
		public static Cipher AES_256_CBC = new Cipher(Native.EVP_aes_256_cbc());
		public static Cipher AES_256_CFB1 = new Cipher(Native.EVP_aes_256_cfb1());
		public static Cipher AES_256_CFB8 = new Cipher(Native.EVP_aes_256_cfb8());
		public static Cipher AES_256_CFB128 = new Cipher(Native.EVP_aes_256_cfb128());
		public static Cipher AES_256_OFB = new Cipher(Native.EVP_aes_256_ofb());
		#endregion

		#region Properties

		public int KeyLength
		{
			get { return this.raw.key_len; }
		}

		public int IVLength
		{
			get { return this.raw.iv_len; }
		}

		public int BlockSize
		{
			get { return this.raw.block_size; }
		}

		public string LongName
		{
			get
			{
				return Native.PtrToStringAnsi(Native.OBJ_nid2ln(this.raw.nid), false);
			}
		}

		public string Name
		{
			get
			{
				return Native.PtrToStringAnsi(Native.OBJ_nid2sn(this.raw.nid), false);
			}
		}

		public int Type
		{
			get
			{
				return Native.EVP_CIPHER_type(this.ptr);
			}
		}

		public string TypeName
		{
			get
			{
				return Native.PtrToStringAnsi(Native.OBJ_nid2ln(this.Type), false);
			}
		}
		#endregion
	}
	#endregion

	public struct Envelope
	{
		public ArraySegment<byte>[] Keys;
		public byte[] IV;
		public byte[] Data;
	}

	public class CipherContext : Base, IDisposable
	{
		#region EVP_CIPHER_CTX
		[StructLayout(LayoutKind.Sequential)]
		struct EVP_CIPHER_CTX
		{
			public IntPtr cipher;
			public IntPtr engine;	/* functional reference if 'cipher' is ENGINE-provided */
			public int encrypt;		/* encrypt or decrypt */
			public int buf_len;		/* number we have left */

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_IV_LENGTH)]
			public byte[] oiv;	/* original iv */
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_IV_LENGTH)]
			public byte[] iv;	/* working iv */
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
			public byte[] buf;/* saved partial block */
			public int num;				/* used by cfb/ofb mode */

			public IntPtr app_data;		/* application stuff */
			public int key_len;		/* May change for variable length cipher */
			public uint flags;	/* Various flags */
			public IntPtr cipher_data; /* per EVP data */
			public int final_used;
			public int block_mask;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
			public byte[] final;/* possible final block */
		}
		#endregion

		private Cipher cipher;

		public CipherContext(Cipher cipher)
			: base(Native.OPENSSL_malloc(Marshal.SizeOf(typeof(EVP_CIPHER_CTX))))
		{
			Native.EVP_CIPHER_CTX_init(this.ptr);
			this.cipher = cipher;
		}

		public override void Print(BIO bio)
		{
			bio.Write("CipherContext: " + this.cipher.LongName);
		}

		#region Methods

		public byte[] Open(byte[] input, byte[] iv, CryptoKey pkey) 
		{
			Native.ExpectSuccess(Native.EVP_OpenInit(
				this.ptr, this.cipher.Handle, input, input.Length, iv, pkey.Handle));

			int len;
			Native.ExpectSuccess(Native.EVP_OpenFinal(this.ptr, null, out len));

			byte[] output = new byte[len];
			Native.ExpectSuccess(Native.EVP_OpenFinal(this.ptr, output, out len));

			return output;
		}

		public Envelope Seal(CryptoKey[] pkeys, bool needsIV) 
		{
			Envelope ret = new Envelope();
			byte[][] bufs = new byte[pkeys.Length][];
			int[] lens = new int[pkeys.Length];
			IntPtr[] pubkeys = new IntPtr[pkeys.Length];
			ret.Keys = new ArraySegment<byte>[pkeys.Length];
			for (int i = 0; i < pkeys.Length; ++i)
			{
				bufs[i] = new byte[pkeys[i].Size];
				lens[i] = pkeys[i].Size;
				pubkeys[i] = pkeys[i].Handle;
			}

			if(needsIV)
				ret.IV = new byte[this.cipher.IVLength];

			int len;
			Native.ExpectSuccess(Native.EVP_SealInit(
				this.ptr, this.cipher.Handle, bufs, lens, ret.IV, pubkeys, pubkeys.Length));
			for (int i = 0; i < pkeys.Length; ++i)
			{
				ret.Keys[i] = new ArraySegment<byte>(bufs[i], 0, lens[i]);
			}

			Native.ExpectSuccess(Native.EVP_SealFinal(this.ptr, null, out len));

			ret.Data = new byte[len];
			Native.ExpectSuccess(Native.EVP_SealFinal(this.ptr, ret.Data, out len));

			return ret;
		}

		public byte[] Crypt(byte[] input, byte[] key, byte[] iv, bool doEncrypt)
		{
			return this.Crypt(input, key, iv, doEncrypt, -1);
		}

		public byte[] Crypt(byte[] input, byte[] key, byte[] iv, bool doEncrypt, int padding)
		{
			int enc = doEncrypt ? 1 : 0;
			int total = input.Length + this.cipher.BlockSize;
			byte[] buf = new byte[total];
			MemoryStream memory = new MemoryStream(total);

			if (key == null)
				key = new byte[this.cipher.KeyLength];

			if (key != null || padding >= 0)
			{
				Native.ExpectSuccess(Native.EVP_CipherInit_ex(
					this.ptr, this.cipher.Handle, IntPtr.Zero, null, null, enc));
				if (key != null)
					Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_key_length(this.ptr, key.Length));
				if (padding >= 0)
					Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_padding(this.ptr, padding));
			}

			Native.ExpectSuccess(Native.EVP_CipherInit_ex(
				this.ptr, this.cipher.Handle, IntPtr.Zero, key, iv, enc));

			int len = buf.Length;
			Native.ExpectSuccess(Native.EVP_CipherUpdate(
				this.ptr, buf, out len, input, input.Length));

			memory.Write(buf, 0, len);

			len = buf.Length;
			Native.EVP_CipherFinal_ex(this.ptr, buf, ref len);

			memory.Write(buf, 0, len);

			return memory.ToArray();
		}

		public byte[] Encrypt(byte[] input, byte[] key, byte[] iv)
		{
			return this.Crypt(input, key, iv, true);
		}

		public byte[] Decrypt(byte[] input, byte[] key, byte[] iv)
		{
			return this.Crypt(input, key, iv, false);
		}

		public byte[] Encrypt(byte[] input, byte[] key, byte[] iv, int padding)
		{
			return this.Crypt(input, key, iv, true, padding);
		}

		public byte[] Decrypt(byte[] input, byte[] key, byte[] iv, int padding)
		{
			return this.Crypt(input, key, iv, false, padding);
		}
		#endregion

		#region Properties
		public Cipher Cipher
		{
			get { return this.cipher; }
		}
		#endregion

		#region IDisposable Members

		public void Dispose()
		{
			Native.EVP_CIPHER_CTX_cleanup(this.ptr);
			Native.OPENSSL_free(this.ptr);
		}

		#endregion
	}
}