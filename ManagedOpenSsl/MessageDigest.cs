using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	#region MessageDigest
	public class MessageDigest : Base
	{
		private EVP_MD raw;
		internal MessageDigest(IntPtr ptr, bool owner) : base(ptr, owner) 
		{
			this.raw = (EVP_MD)Marshal.PtrToStructure(this.ptr, typeof(EVP_MD));
		}

		public override void Print(BIO bio)
		{
			bio.Write("MessageDigest");
		}

		#region EVP_MD
		[StructLayout(LayoutKind.Sequential)]
		struct EVP_MD
		{
			public int type;
			public int pkey_type;
			public int md_size;
			public uint flags;
			public IntPtr init;
			public IntPtr update;
			public IntPtr final;
			public IntPtr copy;
			public IntPtr cleanup;
			public IntPtr sign;
			public IntPtr verify;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
			public int[] required_pkey_type;
			public int block_size;
			public int ctx_size;
		}
		#endregion

		#region MessageDigests
		public static MessageDigest Null = new MessageDigest(Native.EVP_md_null(), false);
		public static MessageDigest MD2 = new MessageDigest(Native.EVP_md2(), false);
		public static MessageDigest MD4 = new MessageDigest(Native.EVP_md4(), false);
		public static MessageDigest MD5 = new MessageDigest(Native.EVP_md5(), false);
		public static MessageDigest SHA = new MessageDigest(Native.EVP_sha(), false);
		public static MessageDigest SHA1 = new MessageDigest(Native.EVP_sha1(), false);
		public static MessageDigest DSS = new MessageDigest(Native.EVP_dss(), false);
		public static MessageDigest DSS1 = new MessageDigest(Native.EVP_dss1(), false);
		public static MessageDigest MDC2 = new MessageDigest(Native.EVP_mdc2(), false);
		public static MessageDigest RipeMD160 = new MessageDigest(Native.EVP_ripemd160(), false);
		#endregion

		#region Properties
		public int BlockSize
		{
			get { return this.raw.block_size; }
		}

		public int Size
		{
			get { return this.raw.md_size; }
		}

		public string LongName
		{
			get
			{
				return Native.PtrToStringAnsi(Native.OBJ_nid2ln(this.raw.type), false);
			}
		}

		public string Name
		{
			get
			{
				return Native.PtrToStringAnsi(Native.OBJ_nid2sn(this.raw.type), false);
			}
		}

		#endregion
	}
	#endregion

	public class MessageDigestContext : Base
	{
		#region EVP_MD_CTX
		[StructLayout(LayoutKind.Sequential)]
		struct EVP_MD_CTX
		{
			public IntPtr digest;
			public IntPtr engine;
			public uint flags;
			public IntPtr md_data;
		}
		#endregion

		private MessageDigest md;

		public MessageDigestContext(BIO bio)
			: base(Native.ExpectNonNull(Native.BIO_get_md_ctx(bio.Handle)), false)
		{
			this.md = new MessageDigest(Native.ExpectNonNull(Native.BIO_get_md(bio.Handle)), false);
		}

		public MessageDigestContext(MessageDigest md)
			: base(Native.EVP_MD_CTX_create(), true)
		{
			Native.EVP_MD_CTX_init(this.ptr);
			this.md = md;
		}

		public override void Print(BIO bio)
		{
			bio.Write("MessageDigestContext: " + this.md.LongName);
		}

		#region Methods

		public byte[] Digest(byte[] msg) 
		{
			byte[] digest = new byte[this.md.Size];
			uint len = (uint)digest.Length;
			Native.ExpectSuccess(Native.EVP_DigestInit_ex(this.ptr, this.md.Handle, IntPtr.Zero));
			Native.ExpectSuccess(Native.EVP_DigestUpdate(this.ptr, msg, (uint)msg.Length));
			Native.ExpectSuccess(Native.EVP_DigestFinal_ex(this.ptr, digest, ref len));
			return digest;
		}

		public byte[] Sign(byte[] msg, CryptoKey pkey) 
		{
			byte[] sig = new byte[pkey.Size];
			uint len = (uint)sig.Length;
			Native.ExpectSuccess(Native.EVP_DigestInit_ex(this.ptr, this.md.Handle, IntPtr.Zero));
			Native.ExpectSuccess(Native.EVP_DigestUpdate(this.ptr, msg, (uint)msg.Length));
			Native.ExpectSuccess(Native.EVP_SignFinal(this.ptr, sig, ref len, pkey.Handle));
			byte[] ret = new byte[len];
			Buffer.BlockCopy(sig, 0, ret, 0, (int)len);
			return ret;
		}

		public static byte[] Sign(MessageDigest md, BIO bio, CryptoKey pkey)
		{
			BIO bmd = BIO.MessageDigest(md);
			bmd.Push(bio);

			while (true)
			{
				ArraySegment<byte> bytes = bmd.ReadBytes(1024 * 4);
				if (bytes.Count == 0)
					break;
			}

			MessageDigestContext ctx = new MessageDigestContext(bmd);

			byte[] sig = new byte[pkey.Size];
			uint len = (uint)sig.Length;
			Native.ExpectSuccess(Native.EVP_SignFinal(ctx.Handle, sig, ref len, pkey.Handle));
			byte[] ret = new byte[len];
			Buffer.BlockCopy(sig, 0, ret, 0, (int)len);
			return ret;
		}

		public bool Verify(byte[] msg, byte[] sig, CryptoKey pkey) 
		{
			Native.ExpectSuccess(Native.EVP_DigestInit_ex(this.ptr, this.md.Handle, IntPtr.Zero));
			Native.ExpectSuccess(Native.EVP_DigestUpdate(this.ptr, msg, (uint)msg.Length));
			int ret = Native.EVP_VerifyFinal(this.ptr, sig, (uint)sig.Length, pkey.Handle);
			if (ret < 0)
				throw new OpenSslException();
			return ret == 1;
		}

		public static bool Verify(MessageDigest md, BIO bio, byte[] sig, CryptoKey pkey)
		{
			BIO bmd = BIO.MessageDigest(md);
			bmd.Push(bio);

			while (true)
			{
				ArraySegment<byte> bytes = bmd.ReadBytes(1024 * 4);
				if (bytes.Count == 0)
					break;
			}

			MessageDigestContext ctx = new MessageDigestContext(bmd);

			int ret = Native.EVP_VerifyFinal(ctx.Handle, sig, (uint)sig.Length, pkey.Handle);
			if (ret < 0)
				throw new OpenSslException();
			return ret == 1;
		}

		#endregion

		#region IDisposable Members

		public override void OnDispose()
		{
			Native.EVP_MD_CTX_cleanup(this.ptr);
			Native.EVP_MD_CTX_destroy(this.ptr);
		}

		#endregion
	}
}