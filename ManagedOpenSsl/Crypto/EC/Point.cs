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

using OpenSSL.Core;
using System;

namespace OpenSSL.Crypto.EC
{
	/// <summary>
	/// Wraps EC_POINT
	/// </summary>
	public class Point : Base
	{
		private Group group;

		#region Initialization
		internal Point(Group group, IntPtr ptr, bool owner)
			: base(ptr, owner)
		{
			this.group = group;
		}

		/// <summary>
		/// Calls EC_POINT_new()
		/// </summary>
		/// <param name="group"></param>
		public Point(Group group)
			: base(Native.EC_POINT_new(group.Handle), true)
		{
			this.group = group;
		}
		#endregion

		#region Properties
		#endregion

		#region Methods
		/// <summary>
		/// Calls EC_POINT_get_affine_coordinates_GF2m()
		/// </summary>
		/// <param name="x"></param>
		/// <param name="y"></param>
		/// <param name="ctx"></param>
		public void GetAffineCoordinatesGF2m(BigNumber x, BigNumber y, BigNumber.Context ctx)
		{
			Native.ExpectSuccess(
				Native.EC_POINT_get_affine_coordinates_GF2m(group.Handle, ptr, x.Handle, y.Handle, ctx.Handle)
			);
		}

		/// <summary>
		/// Calls EC_POINT_get_affine_coordinates_GFp()
		/// </summary>
		/// <param name="x"></param>
		/// <param name="y"></param>
		/// <param name="ctx"></param>
		public void GetAffineCoordinatesGFp(BigNumber x, BigNumber y, BigNumber.Context ctx)
		{
			Native.ExpectSuccess(
				Native.EC_POINT_get_affine_coordinates_GFp(group.Handle, ptr, x.Handle, y.Handle, ctx.Handle)
			);
		}
		#endregion

		#region Overrides
		/// <summary>
		/// Calls EC_POINT_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.EC_POINT_free(this.ptr);
		}
		#endregion
	}
}

