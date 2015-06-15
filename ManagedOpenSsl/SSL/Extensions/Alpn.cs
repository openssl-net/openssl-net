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
    /// <summary>
    /// 
    /// </summary>
    /// <param name="ssl"></param>
    /// <param name="selProto"></param>
    /// <param name="selProtoLen"></param>
    /// <param name="inProtos"></param>
    /// <param name="inProtosLen"></param>
    /// <param name="arg"></param>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int AlpnCallback(IntPtr ssl,
                                     [MarshalAs(UnmanagedType.LPStr)] out string selProto,
                                     [MarshalAs(UnmanagedType.U1)] out byte selProtoLen,
                                     IntPtr inProtos, int inProtosLen, IntPtr arg);

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
            if (offset1 + count > protos1.Length
                || offset2 + count > protos2.Length)
            {
                return false;
            }

            for (int i = 0; i < count; i ++)
            {
                if (protos1[i + offset1] != protos2[i + offset2])
                    return false;
            }

            return true;
        }

        private void SetKnownProtocols(IntPtr ctx, IEnumerable<string> protos)
        {
            using (var protoStream = new MemoryStream())
            {
                int offset = 0;
                foreach (var proto in protos)
                {
                    byte protoLen = (byte) proto.Length;
                    protoStream.WriteByte(protoLen);

                    var protoBf = Encoding.UTF8.GetBytes(proto);
                    protoStream.Write(protoBf, 0, protoLen);

                    offset += protoLen + sizeof(byte);
                }

                _knownProtocols = new byte[offset];
                Buffer.BlockCopy(protoStream.GetBuffer(), 0, _knownProtocols, 0, offset);
            }

            if (Native.SSL_CTX_set_alpn_protos(ctx, _knownProtocols, (UInt32)_knownProtocols.Length) != 0)
                throw new AlpnException("cant set alpn protos");
        }

        public int AlpnCb(IntPtr ssl, 
                                 [MarshalAs(UnmanagedType.LPStr)] out string selProto, 
                                 [MarshalAs(UnmanagedType.U1)] out byte selProtoLen,
                                 IntPtr inProtos, int inProtosLen, IntPtr arg)
        {
            var inProtosBytes = new byte[inProtosLen];

            for (int i = 0; i < inProtosLen; i++)
            {
                inProtosBytes[i] = Marshal.ReadByte(inProtos, i);
            }

            int matchIndex = -1;
            byte matchLen = 0;
            for (int i = 0; i < _knownProtocols.Length; )
            {
                bool gotMatch = false;
                for (int j = 0; j < inProtosLen; )
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
                return (int) Errors.SSL_TLSEXT_ERR_NOACK;
            }

            selProto = Encoding.UTF8.GetString(_knownProtocols, matchIndex + 1, matchLen);

            selProtoLen = matchLen;
            return (int) Errors.SSL_TLSEXT_ERR_OK; //ok OPENSSL_NPN_NEGOTIATED
        }
    }
}
