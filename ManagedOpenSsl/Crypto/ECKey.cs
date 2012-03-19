// Copyright (c) 2012 Frank Laub
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
using System;
using System.Runtime.InteropServices;

namespace OpenSSL.Core
{
	public class ECKey : BaseCopyableRef<ECKey>
	{
		[StructLayout(LayoutKind.Sequential)]
		struct ec_key_st 
		{
			public int version;
			public IntPtr group;
			public IntPtr pub_key;
			public IntPtr priv_key;
			public uint enc_flag;
			public int conv_form;
			public int references;
			public IntPtr method_data;
		}
		
		#region Initialization
		internal ECKey(IntPtr ptr, bool owner) 
			: base(ptr, owner) { 
		}

		public ECKey()
			: base(Native.ExpectNonNull(Native.EC_KEY_new()), true) {
		}
		
		public static ECKey FromCurveName(Asn1Object obj) {
			return new ECKey(Native.ExpectNonNull(Native.EC_KEY_new_by_curve_name(obj.NID)), true);
		}
		#endregion

		#region Properties
		public int Size {
			get { return Native.ECDSA_size(this.ptr); }
		}
		
		public ECGroup Group {
			get { return new ECGroup(Native.ExpectNonNull(Native.EC_KEY_get0_group(this.ptr)), false); }
			set { Native.ExpectSuccess(Native.EC_KEY_set_group(this.ptr, value.Handle)); }
		}
		#endregion

		#region Methods
		public void GenerateKey() {
			Native.ExpectSuccess(Native.EC_KEY_generate_key(this.ptr));
		}
		
		public bool CheckKey() {
			return Native.ExpectSuccess(Native.EC_KEY_check_key(this.ptr)) == 1;
		}
		
		public ECDSASignature Sign(byte[] digest) {
			IntPtr sig = Native.ExpectNonNull(Native.ECDSA_do_sign(digest, digest.Length, this.ptr));
			return new ECDSASignature(sig, true);
		}
		
		public uint Sign(int type, byte[] digest, byte[] sig) {
			uint siglen = (uint)sig.Length;
			Native.ExpectSuccess(Native.ECDSA_sign(type, digest, digest.Length, sig, ref siglen, this.ptr));
			return siglen;
		}
		
		public bool Verify(byte[] digest, ECDSASignature sig) {
			return Native.ECDSA_do_verify(digest, digest.Length, sig.Handle, this.ptr) == 1;
		}
		
		public bool Verify(int type, byte[] digest, byte[] sig) {
			return Native.ECDSA_verify(type, digest, digest.Length, sig, sig.Length, this.ptr) == 1;
		}
		#endregion

		#region Overrides
		protected override void OnDispose() {
			Native.EC_KEY_free(this.ptr);
		}

		internal override CryptoLockTypes LockType {
			get { return CryptoLockTypes.CRYPTO_LOCK_ECDSA; }
		}

		internal override Type RawReferenceType {
			get { return typeof(ec_key_st); }
		}
		#endregion
	}
	
	public class ECDSASignature : Base
	{
		[StructLayout(LayoutKind.Sequential)]
		struct ECDSA_SIG_st
		{
			public IntPtr r;
			public IntPtr s;
		}

		#region Initialization
		internal ECDSASignature(IntPtr ptr, bool owner) 
			: base(ptr, owner) {
		}
		
		public ECDSASignature() 
			: base(Native.ExpectNonNull(Native.ECDSA_SIG_new()), true) {
		}
		#endregion

		#region Properties
		private ECDSA_SIG_st Raw {
			get { return (ECDSA_SIG_st)Marshal.PtrToStructure(this.ptr, typeof(ECDSA_SIG_st)); }
			set { Marshal.StructureToPtr(value, this.ptr, false); }
		}

		public BigNumber R {
			get { return new BigNumber(this.Raw.r, false); }
		}

		public BigNumber S {
			get { return new BigNumber(this.Raw.s, false); }
		}
		#endregion

		#region Methods
		#endregion

		#region Overrides
		protected override void OnDispose() {
			Native.ECDSA_SIG_free(this.ptr);
		}
		#endregion
	}
	
	public class ECBuiltinCurve
	{
		[StructLayout(LayoutKind.Sequential)]
		private struct EC_builtin_curve
		{
			public int nid;
			public string comment;
		}
		
		private Asn1Object obj;
		private string comment;
		
		private ECBuiltinCurve(int nid, string comment) {
			this.obj = new Asn1Object(nid);
			this.comment = comment;
		}
		
		public Asn1Object Object { get { return this.obj; } }
		public string Comment { get { return this.comment; } }
		
		public static ECBuiltinCurve[] Get() {
			int count = Native.EC_get_builtin_curves(IntPtr.Zero, 0);
			ECBuiltinCurve[] curves = new ECBuiltinCurve[count];
			IntPtr ptr = Native.OPENSSL_malloc(Marshal.SizeOf(typeof(EC_builtin_curve)) * count);
			try {
				Native.ExpectSuccess(Native.EC_get_builtin_curves(ptr, count));
				IntPtr pItem = ptr;
				for (int i = 0; i < count; i++) {
					EC_builtin_curve raw = (EC_builtin_curve)Marshal.PtrToStructure(pItem, typeof(EC_builtin_curve));
					curves[i] = new ECBuiltinCurve(raw.nid, raw.comment);
					pItem = new IntPtr(pItem.ToInt64() + Marshal.SizeOf(typeof(EC_builtin_curve)));
				}
			}
			finally {
				Native.OPENSSL_free(ptr);
			}
			return curves;
		}
	}
	
	public class ECMethod : Base
	{
		internal ECMethod(IntPtr ptr, bool owner) 
			: base(ptr, owner) { 
		}

		#region Overrides
		protected override void OnDispose() {
		}
		#endregion
	}
	
	public class ECGroup : Base
	{
		#region Initialization
		internal ECGroup(IntPtr ptr, bool owner) 
			: base(ptr, owner) { 
		}

		public ECGroup(ECMethod method)
			: base(Native.ExpectNonNull(Native.EC_GROUP_new(method.Handle)), true) {
		}
		
		public static ECGroup FromCurveName(Asn1Object obj) {
			return new ECGroup(Native.ExpectNonNull(Native.EC_GROUP_new_by_curve_name(obj.NID)), true);
		}
		#endregion

		#region Properties
		public int Degree {
			get { return Native.EC_GROUP_get_degree(this.ptr); }
		}
		#endregion

		#region Methods
		#endregion

		#region Overrides
		protected override void OnDispose() {
			Native.EC_GROUP_free(this.ptr);
		}
		#endregion
	}
}

