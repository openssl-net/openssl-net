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
using System.Net.Security;
using System.IO;

namespace OpenSSL
{
    public delegate bool RemoteCertificateValidationCallback(Object sender, X509Certificate cert, X509Chain chain, int depth, VerifyResult result);
    public delegate X509Certificate LocalCertificateSelectionCallback(Object sender, string targetHost, X509List localCerts, X509Certificate remoteCert, string[] acceptableIssuers);

    public enum SslProtocols
    {
        None = 0,
        Ssl2 = 1,
        Ssl3 = 2,
        Tls  = 4,
        Default = 16 
    }

    public enum SslStrength
    {
        High,   //256
        Medium, //128
        Low     //40
    }

    public class SslStream : AuthenticatedStream
    {
        protected SslStreamBase sslStream;
        protected RemoteCertificateValidationCallback remoteCertificateValidationCallback = null;
        protected LocalCertificateSelectionCallback localCertificateSelectionCallback = null;
        protected bool m_bCheckCertRevocationStatus = false;

        public SslStream(Stream stream)
            : this(stream, false)
        {
        }

        public SslStream(Stream stream, bool leaveInnerStreamOpen)
            : base(stream, leaveInnerStreamOpen)
        {
            remoteCertificateValidationCallback = null;
            localCertificateSelectionCallback = null;
        }

        public SslStream(Stream stream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback remote_callback)
            : this(stream, leaveInnerStreamOpen, remote_callback, null)
        {
        }

        public SslStream(Stream stream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback remote_callback, LocalCertificateSelectionCallback local_callback)
            : base(stream, leaveInnerStreamOpen)
        {
            remoteCertificateValidationCallback = remote_callback;
            localCertificateSelectionCallback = local_callback;
        }

        #region Properties
        public override bool IsAuthenticated
        {
            get { return sslStream != null; }
        }

        public override bool IsEncrypted
        {
            get { return IsAuthenticated; }
        }

        public override bool IsMutuallyAuthenticated
        {
            get
            {
                if (IsAuthenticated && (IsServer ? sslStream.RemoteCertificate != null : sslStream.LocalCertificate != null))
                {
                    return true;
                }
                return false;
            }
        }

        public override bool IsServer
        {
            get { return sslStream is SslStreamServer; }
        }

        public override bool IsSigned
        {
            get { return IsAuthenticated; }
        }

        public override bool CanRead
        {
            get { return InnerStream.CanRead; }
        }

        public override bool CanSeek
        {
            get { return InnerStream.CanSeek; }
        }

        public override bool CanWrite
        {
            get { return InnerStream.CanWrite; }
        }

        public override void Flush()
        {
            InnerStream.Flush();
        }

        public override long Length
        {
            get { return InnerStream.Length; }
        }

        public override long Position
        {
            get
            {
                return InnerStream.Position;
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        public bool CheckCertificateRevocationStatus
        {
            get
            {
                if (!IsAuthenticated)
                {
                    return false;
                }
                return sslStream.CheckCertificateRevocationStatus;
            }
        }

        public CipherAlgorithmType CipherAlgorithm
        {
            get
            {
                if (!IsAuthenticated)
                {
                    return CipherAlgorithmType.None;
                }
                return sslStream.CipherAlgorithm;
            }
        }

        public int CipherStrength
        {
            get
            {
                if (!IsAuthenticated)
                {
                    return 0;
                }
                return sslStream.CipherStrength;
            }
        }
        
        public HashAlgorithmType HashAlgorithm
        {
            get
            {
                if (! IsAuthenticated)
                {
                    return HashAlgorithmType.None;
                }
                return sslStream.HashAlgorithm;
            }
        }

        public int HashStrength
        {
            get
            {
                if (! IsAuthenticated)
                {
                    return 0;
                }
                return sslStream.HashStrength;
            }
        }
        
        public ExchangeAlgorithmType KeyExchangeAlgorithm
        {
            get
            {
                if (! IsAuthenticated)
                {
                    return ExchangeAlgorithmType.None; 
                }
                return sslStream.KeyExchangeAlgorithm;
            }
        }
        
        public int KeyExchangeStrength
        {
            get
            {
                if (! IsAuthenticated)
                {
                    return 0;
                }
                return sslStream.KeyExchangeStrength;
            }
        }

        public X509Certificate LocalCertificate
        {
            get
            {
                if (! IsAuthenticated)
                {
                    return null;
                }
                return sslStream.LocalCertificate;
            }
        }

        public virtual X509Certificate RemoteCertificate
        {
            get
            {
                if (! IsAuthenticated)
                {
                    return null;
                }
                return sslStream.RemoteCertificate;
            }
        }

        public SslProtocols SslProtocol
        {
            get
            {
                if (!IsAuthenticated)
                {
                    return SslProtocols.None;
                }
                return sslStream.SslProtocol;
            }
        }
        
        public override int ReadTimeout
        {
            get
            {
                return InnerStream.ReadTimeout;
            }
            set
            {
                InnerStream.ReadTimeout = value;
            }
        }

        public override int WriteTimeout
        {
            get
            {
                return InnerStream.WriteTimeout;
            }
            set
            {
                InnerStream.WriteTimeout = value;
            }
        }
        #endregion //Properties

        #region Methods
        public virtual void AuthenticateAsClient(string targetHost)
        {
            AuthenticateAsClient(targetHost, null, null, SslProtocols.Default, SslStrength.Medium, false);
        }

        public virtual void AuthenticateAsClient(
            string targetHost,
            X509List certificates,
            X509Chain caCertificates,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            bool checkCertificateRevocation)
        {
            EndAuthenticateAsClient(BeginAuthenticateAsClient(targetHost, certificates, caCertificates, enabledSslProtocols, sslStrength, checkCertificateRevocation, null, null));
        }

        public virtual IAsyncResult BeginAuthenticateAsClient(string targetHost, AsyncCallback asyncCallback, Object asyncState)
        {
            return BeginAuthenticateAsClient(targetHost, null, null, SslProtocols.Default, SslStrength.Medium, false, asyncCallback, asyncState);
        }

        public virtual IAsyncResult BeginAuthenticateAsClient(
            string targetHost,
            X509List clientCertificates,
            X509Chain caCertificates,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            bool checkCertificateRevocation, 
            AsyncCallback asyncCallback, 
            Object asyncState)
        {
            if (IsAuthenticated)
            {
                throw new InvalidOperationException("SslStream is already authenticated");
            }

            // Create the stream
            SslStreamClient client_stream = new SslStreamClient(InnerStream, false, targetHost, clientCertificates, caCertificates, enabledSslProtocols, sslStrength, checkCertificateRevocation, remoteCertificateValidationCallback, localCertificateSelectionCallback);
            // set the internal stream
            sslStream = client_stream;
            // start the write operation
            return BeginWrite(new byte[0], 0, 0, asyncCallback, asyncState);
        }

        public virtual void EndAuthenticateAsClient(IAsyncResult ar)
        {
            IsConnectionValid();

            // Finish the async authentication.  The EndRead/EndWrite will complete successfully, or throw exception
            EndWrite(ar);
        }

        public virtual void AuthenticateAsServer(X509Certificate serverCertificate)
        {
            AuthenticateAsServer(serverCertificate, false, null, SslProtocols.Default, SslStrength.Medium, false);
        }

        public virtual void AuthenticateAsServer(
            X509Certificate serverCertificate,
            bool clientCertificateRequired, 
            X509Chain caCertificates,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            bool checkCertificateRevocation)
        {
            EndAuthenticateAsServer(BeginAuthenticateAsServer(serverCertificate, clientCertificateRequired, caCertificates, enabledSslProtocols, sslStrength, checkCertificateRevocation, null, null));
        }

        public virtual IAsyncResult BeginAuthenticateAsServer(
            X509Certificate serverCertificate, 
            AsyncCallback asyncCallback,
            Object asyncState)
        {
            return BeginAuthenticateAsServer(serverCertificate, false, null, SslProtocols.Default, SslStrength.Medium, false, asyncCallback, asyncState);
        }

        public virtual IAsyncResult BeginAuthenticateAsServer(
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            X509Chain caCerts,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            bool checkCertificateRevocation,
            AsyncCallback asyncCallback,
            Object asyncState)
        {
            if (IsAuthenticated)
            {
                throw new InvalidOperationException("SslStream is already authenticated");
            }
            // Initialize the server stream
            SslStreamServer server_stream = new SslStreamServer(InnerStream, false, serverCertificate, clientCertificateRequired, caCerts, enabledSslProtocols, sslStrength, checkCertificateRevocation, remoteCertificateValidationCallback);
            // Set the internal sslStream
            sslStream = server_stream;
            // Start the read operation
            return BeginRead(new byte[0], 0, 0, asyncCallback, asyncState);
        }

        public virtual void EndAuthenticateAsServer(IAsyncResult ar)
        {
            IsConnectionValid();

            // Finish the async AuthenticateAsServer call - EndRead/Write call will throw exception on error
            EndRead(ar);
        }

        public void Renegotiate()
        {
            IsConnectionValid();

            EndRenegotiate(BeginRenegotiate(null, null));
        }

        public IAsyncResult BeginRenegotiate(AsyncCallback callback, object state)
        {
            IsConnectionValid();

            sslStream.Renegotiate();

            if (sslStream is SslStreamClient)
            {
                return BeginWrite(new byte[0], 0, 0, callback, state);
            }
            else
            {
                return BeginRead(new byte[0], 0, 0, callback, state);
            }
        }

        public void EndRenegotiate(IAsyncResult asyncResult)
        {
            IsConnectionValid();

            if (sslStream is SslStreamClient)
            {
                EndWrite(asyncResult);
            }
            else
            {
                EndRead(asyncResult);
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return EndRead(BeginRead(buffer, offset, count, null, null));
        }

        public override IAsyncResult BeginRead(
            byte[] buffer,
            int offset,
            int count,
            AsyncCallback asyncCallback,
            Object asyncState)
        {
            IsConnectionValid();

            return sslStream.BeginRead(buffer, offset, count, asyncCallback, asyncState);
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            IsConnectionValid();

            return sslStream.EndRead(asyncResult);
        }

        public override long Seek(long offset, System.IO.SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            InnerStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            IsConnectionValid();

            EndWrite(BeginWrite(buffer, offset, count, null, null));
        }

        public override IAsyncResult BeginWrite(
            byte[] buffer,
            int offset,
            int count,
            AsyncCallback asyncCallback,
            Object asyncState)
        {
            IsConnectionValid();

            return sslStream.BeginWrite(buffer, offset, count, asyncCallback, asyncState);
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            IsConnectionValid();

            sslStream.EndWrite(asyncResult);
        }

        public override void Close()
        {
            IsConnectionValid();

            base.Close();
            sslStream.Close();
        }
        #endregion

        private void IsConnectionValid()
        {
            if (sslStream == null)
            {
                throw new InvalidOperationException("SslStream has not been authenticated");
            }
        }
    }
}
