// Copyright © Microsoft Open Technologies, Inc.
// All Rights Reserved       

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using OpenSSL.Core;
using OpenSSL.Exceptions;
using OpenSSL.SSL;

namespace OpenSSL.Extensions
{
	internal class AlpnExtension
	{
		internal AlpnExtension(IntPtr ctxHandle, IEnumerable<string> knownProtos)
		{
			if (knownProtos == null)
				throw new ArgumentNullException("knownProtos");

			SetKnownProtocols(ctxHandle, knownProtos);
		}

		private byte[] _knownProtocols;

		private bool CompareProtos(byte[] protos1, int offset1, byte[] protos2, int offset2, int count)
		{
			if (offset1 + count > protos1.Length ||
			    offset2 + count > protos2.Length)
			{
				return false;
			}

			for (int i = 0; i < count; i++)
			{
				if (protos1[i + offset1] != protos2[i + offset2])
					return false;
			}

			return true;
		}

		private void SetKnownProtocols(IntPtr ctx, IEnumerable<string> protos)
		{
			uint total = 0;
			using (var protoStream = new MemoryStream())
			{
				foreach (var proto in protos)
				{
					byte len = (byte)proto.Length;
					protoStream.WriteByte(len);

					var utf8 = Encoding.UTF8.GetBytes(proto);
					protoStream.Write(utf8, 0, len);

					total += sizeof(byte) + (uint)len;
				}

				_knownProtocols = protoStream.GetBuffer();
			}

			if (Native.SSL_CTX_set_alpn_protos(ctx, _knownProtocols, total) != 0)
			{
				throw new AlpnException("cant set alpn protos");
			}
		}

		public int AlpnCb(IntPtr ssl, 
			out string selProto, 
			out byte selProtoLen,
			IntPtr inProtos, 
			int inProtosLen, 
			IntPtr arg)
		{
			var inProtosBytes = new byte[inProtosLen];
			Marshal.Copy(inProtos, inProtosBytes, 0, inProtosLen);

			int matchIndex = -1;
			byte matchLen = 0;
			for (int i = 0; i < _knownProtocols.Length;)
			{
				bool gotMatch = false;
				for (int j = 0; j < inProtosLen;)
				{
					if (_knownProtocols[i] == inProtosBytes[j] &&
					    CompareProtos(_knownProtocols, i + 1, inProtosBytes, j + 1, _knownProtocols[i]))
					{
						/* We found a match */
						matchIndex = i;
						matchLen = _knownProtocols[i];
						gotMatch = true;
						break;
					}

					j += inProtosBytes[j];
					j++;
				}

				if (gotMatch)
					break;

				i += _knownProtocols[i];
				i++;
			}

			if (matchIndex == -1)
			{
				selProto = null;
				selProtoLen = 0;
				return (int)Errors.SSL_TLSEXT_ERR_NOACK;
			}

			selProto = Encoding.UTF8.GetString(_knownProtocols, matchIndex + 1, matchLen);

			selProtoLen = matchLen;
			return (int)Errors.SSL_TLSEXT_ERR_OK; // ok OPENSSL_NPN_NEGOTIATED
		}
	}
}
