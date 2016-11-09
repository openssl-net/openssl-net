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

using OpenSSL.Core;
using OpenSSL.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using OpenSSL.Extensions;

namespace OpenSSL.SSL
{
	internal abstract class SslStreamBase : Stream
	{
		internal Stream innerStream;
		private volatile bool disposed = false;
		internal SslContext sslContext;
		internal Ssl ssl;
		internal BIO read_bio;
		internal BIO write_bio;
		// for reading from the stream
		private byte[] read_buffer = new byte[16384];
		// decrypted data from Ssl.Read
		private MemoryStream cleartext = new MemoryStream();
		private const int SSL3_RT_HEADER_LENGTH = 5;
		private const int SSL3_RT_MAX_PLAIN_LENGTH = 16384;
		private const int SSL3_RT_MAX_COMPRESSED_LENGTH = (1024 + SSL3_RT_MAX_PLAIN_LENGTH);
		private const int SSL3_RT_MAX_ENCRYPTED_LENGTH = (1024 + SSL3_RT_MAX_COMPRESSED_LENGTH);
		private const int SSL3_RT_MAX_PACKET_SIZE = (SSL3_RT_MAX_ENCRYPTED_LENGTH + SSL3_RT_HEADER_LENGTH);
		// 5 minutes
		private const int WaitTimeOut = 300 * 1000;
		protected LocalCertificateSelectionHandler OnLocalCertificate;
		protected RemoteCertificateValidationHandler OnRemoteCertificate;
		protected bool checkCertificateRevocationStatus = false;
		protected HandshakeState handShakeState = HandshakeState.None;
		protected OpenSslException handshakeException = null;

		protected SniCallback sniCb;
		protected Sni sniExt;

		protected string srvName = "localhost";

		/// <summary>
		/// Override to implement client/server specific handshake processing
		/// </summary>
		/// <returns></returns>
		internal protected abstract bool ProcessHandshake();

		#region InternalAsyncResult class

		private class InternalAsyncResult : IAsyncResult
		{
			private object locker = new object();
			private AsyncCallback userCallback;
			private object userState;
			private Exception asyncException;
			private ManualResetEvent asyncWaitHandle;
			private bool isCompleted;
			private int bytesRead;
			private bool isWriteOperation;
			private bool continueAfterHandshake;

			private byte[] buffer;
			private int offset;
			private int count;

			public InternalAsyncResult(
				AsyncCallback userCallback,
				object userState,
				byte[] buffer,
				int offset,
				int count,
				bool isWriteOperation,
				bool continueAfterHandshake)
			{
				this.userCallback = userCallback;
				this.userState = userState;
				this.buffer = buffer;
				this.offset = offset;
				this.count = count;
				this.isWriteOperation = isWriteOperation;
				this.continueAfterHandshake = continueAfterHandshake;
			}

			public bool ContinueAfterHandshake
			{
				get { return continueAfterHandshake; }
			}

			public bool IsWriteOperation
			{
				get { return isWriteOperation; }
				set { isWriteOperation = value; }
			}

			public byte[] Buffer
			{
				get { return buffer; }
			}

			public int Offset
			{
				get { return offset; }
			}

			public int Count
			{
				get { return count; }
			}

			public int BytesRead
			{
				get { return bytesRead; }
			}

			public object AsyncState
			{
				get { return userState; }
			}

			public Exception AsyncException
			{
				get { return asyncException; }
			}

			public bool CompletedWithError
			{
				get
				{
					if (IsCompleted == false)
					{
						return false;
					}
					return (null != asyncException);
				}
			}

			public WaitHandle AsyncWaitHandle
			{
				get
				{
					lock (locker)
					{
						// Create the event if we haven't already done so
						if (asyncWaitHandle == null)
						{
							asyncWaitHandle = new ManualResetEvent(isCompleted);
						}
					}
					return asyncWaitHandle;
				}
			}

			public bool CompletedSynchronously
			{
				get { return false; }
			}

			public bool IsCompleted
			{
				get
				{
					lock (locker)
					{
						return isCompleted;
					}
				}
			}

			private void SetComplete(Exception ex, int bytesRead)
			{
				lock (locker)
				{
					if (isCompleted)
					{
						return;
					}

					isCompleted = true;
					asyncException = ex;
					this.bytesRead = bytesRead;
					// If the wait handle isn't null, we should set the event
					// rather than fire a callback
					if (asyncWaitHandle != null)
					{
						asyncWaitHandle.Set();
					}
				}
				// If we have a callback method, invoke it
				if (userCallback != null)
				{
					userCallback.BeginInvoke(this, null, null);
				}
			}

			public void SetComplete(Exception ex)
			{
				SetComplete(ex, 0);
			}

			public void SetComplete(int bytesRead)
			{
				SetComplete(null, bytesRead);
			}

			public void SetComplete()
			{
				SetComplete(null, 0);
			}
		}

		#endregion

		public SslStreamBase(Stream stream)
		{
			if (stream == null)
			{
				throw new ArgumentNullException("stream");
			}
			if (!stream.CanRead || !stream.CanWrite)
			{
				throw new ArgumentException("Stream must allow read and write capabilities", "stream");
			}
			innerStream = stream;
            
			sniExt = new Sni(srvName);
		}

		public bool HandshakeComplete
		{
			get { return handShakeState == HandshakeState.Complete; }
		}

		private bool NeedHandshake
		{
			get { return ((handShakeState == HandshakeState.None) || (handShakeState == HandshakeState.Renegotiate)); }
		}

		public bool CheckCertificateRevocationStatus
		{
			get { return checkCertificateRevocationStatus; }
			set { checkCertificateRevocationStatus = value; }
		}

		public LocalCertificateSelectionHandler LocalCertSelectionCallback
		{
			get { return OnLocalCertificate; }
			set { OnLocalCertificate = value; }
		}

		public RemoteCertificateValidationHandler RemoteCertValidationCallback
		{
			get { return OnRemoteCertificate; }
			set { OnRemoteCertificate = value; }
		}

		public Ssl Ssl
		{
			get { return ssl; }
		}

		#region Stream methods

		public override bool CanRead
		{
			get { return innerStream.CanRead; }
		}

		public override bool CanSeek
		{
			get { return innerStream.CanSeek; }
		}

		public override bool CanWrite
		{
			get { return innerStream.CanWrite; }
		}

		public override void Flush()
		{
			if (disposed)
			{
				throw new ObjectDisposedException("SslStreamBase");
			}
			innerStream.Flush();
		}

		public override long Length
		{
			get { return innerStream.Length; }
		}

		public override long Position
		{
			get { return innerStream.Position; }
			set { throw new NotSupportedException(); }
		}

		public override int ReadTimeout
		{
			get { return innerStream.ReadTimeout; }
			set { innerStream.ReadTimeout = value; }
		}

		public override int WriteTimeout
		{
			get { return innerStream.WriteTimeout; }
			set { innerStream.WriteTimeout = value; }
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotImplementedException();
		}

		public override void SetLength(long value)
		{
			innerStream.SetLength(value);
		}

		//!! - not implementing blocking read, but using BeginRead with no callbacks
		public override int Read(byte[] buffer, int offset, int count)
		{
			throw new NotImplementedException();
		}

		public void SendShutdownAlert()
		{
			if (disposed)
				return;

			var nShutdownRet = ssl.Shutdown();
			if (nShutdownRet == 0)
			{
				var nBytesToWrite = write_bio.BytesPending;
				if (nBytesToWrite <= 0)
				{
					// unexpected error
					//!!TODO log error
					return;
				}
				var buf = write_bio.ReadBytes((int)nBytesToWrite);
				if (buf.Count <= 0)
				{
					//!!TODO - log error
				}
				else
				{
					// Write the shutdown alert to the stream
					innerStream.Write(buf.Array, 0, buf.Count);
				}
			}
		}

		public override IAsyncResult BeginRead(
			byte[] buffer,
			int offset,
			int count,
			AsyncCallback asyncCallback,
			object asyncState)
		{
			if (buffer == null)
			{
				throw new ArgumentNullException("buffer", "buffer can't be null");
			}
			if (offset < 0)
			{
				throw new ArgumentOutOfRangeException("offset", "offset less than 0");
			}
			if (offset > buffer.Length)
			{
				throw new ArgumentOutOfRangeException("offset", "offset must be less than buffer length");
			}
			if (count < 0)
			{
				throw new ArgumentOutOfRangeException("count", "count less than 0");
			}
			if (count > (buffer.Length - offset))
			{
				throw new ArgumentOutOfRangeException("count", "count is greater than buffer length - offset");
			}

			var proceedAfterHandshake = count != 0;

			var internalAsyncResult = new InternalAsyncResult(
				asyncCallback, 
				asyncState, 
				buffer, 
				offset, 
				count, 
				false, 
				proceedAfterHandshake);

			if (NeedHandshake)
			{
				BeginHandshake(internalAsyncResult);
			}
			else
			{
				InternalBeginRead(internalAsyncResult);
			}

			return internalAsyncResult;
		}

		private void InternalBeginRead(InternalAsyncResult asyncResult)
		{
			if (disposed)
				return;

			// Check to see if the decrypted data stream should be reset
			if (cleartext.Position == cleartext.Length)
			{
				cleartext.Seek(0, SeekOrigin.Begin);
				cleartext.SetLength(0);
			}
			// Check to see if we have data waiting in the decrypted data stream
			if (cleartext.Length > 0 && (cleartext.Position != cleartext.Length))
			{
				// Process the pre-existing data
				var bytesRead = cleartext.Read(asyncResult.Buffer, asyncResult.Offset, asyncResult.Count);
				asyncResult.SetComplete(bytesRead);
				return;
			}
			// Start the async read from the inner stream
			innerStream.BeginRead(read_buffer, 0, read_buffer.Length, InternalReadCallback, asyncResult);
		}

		private void InternalReadCallback(IAsyncResult asyncResult)
		{
			if (disposed)
				return;

			var internalAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;
			var haveDataToReturn = false;

			try
			{
				var bytesRead = 0;
				try
				{
					bytesRead = innerStream.EndRead(asyncResult);
				}
				catch (Exception ex)
				{
					// Set the exception into the internal async result
					internalAsyncResult.SetComplete(ex);
				}
				if (bytesRead <= 0)
				{
					// Zero byte read most likely indicates connection closed (if it's a network stream)
					internalAsyncResult.SetComplete(0);
					throw new IOException("Connection was closed by the remote endpoint");
				}
				else
				{
					// Copy encrypted data into the SSL read_bio
					read_bio.Write(read_buffer, bytesRead);
					if (handShakeState == HandshakeState.InProcess ||
					    handShakeState == HandshakeState.RenegotiateInProcess)
					{
						// We are in the handshake, complete the async operation to fire the async
						// handshake callback for processing
						internalAsyncResult.SetComplete(bytesRead);
						return;
					}
					var nBytesPending = read_bio.BytesPending;
					var decrypted_buf = new byte[SSL3_RT_MAX_PACKET_SIZE];
					while (nBytesPending > 0)
					{
						int decryptedBytesRead = ssl.Read(decrypted_buf, decrypted_buf.Length);
						if (decryptedBytesRead <= 0)
						{
							var lastError = ssl.GetError(decryptedBytesRead);
							if (lastError == SslError.SSL_ERROR_WANT_READ)
							{
								// if we have bytes pending in the write bio.
								// the client has requested a renegotiation
								if (write_bio.BytesPending > 0)
								{
									// Start the renegotiation by writing the write_bio data, and use the RenegotiationWriteCallback
									// to handle the rest of the renegotiation
									var buf = write_bio.ReadBytes((int)write_bio.BytesPending);
									innerStream.BeginWrite(
										buf.Array, 0, buf.Count,
										RenegotiationWriteCallback,
										internalAsyncResult);
									return;
								}
								// no data in the out bio, we just need more data to complete the record
								//break;
							}
							else if (lastError == SslError.SSL_ERROR_WANT_WRITE)
							{
								// unexpected error!
								//!!TODO debug log
							}
							else if (lastError == SslError.SSL_ERROR_ZERO_RETURN)
							{
								// Shutdown alert
								SendShutdownAlert();
								break;
							}
							else
							{
								//throw new OpenSslException();
							}
						}
						if (decryptedBytesRead > 0)
						{
							// Write decrypted data to memory stream
							var pos = cleartext.Position;
							cleartext.Seek(0, SeekOrigin.End);
							cleartext.Write(decrypted_buf, 0, decryptedBytesRead);
							cleartext.Seek(pos, SeekOrigin.Begin);
							haveDataToReturn = true;
						}

						// See if we have more data to process
						nBytesPending = read_bio.BytesPending;
					}
					// Check to see if we have data to return, if not, fire the async read again
					if (!haveDataToReturn)
					{
						innerStream.BeginRead(
							read_buffer, 0, read_buffer.Length, 
							InternalReadCallback,
							internalAsyncResult);
					}
					else
					{
						var bytesReadIntoUserBuffer = 0;

						// Read the data into the buffer provided by the user (now hosted in the InternalAsyncResult)
						bytesReadIntoUserBuffer = cleartext.Read(internalAsyncResult.Buffer,
							internalAsyncResult.Offset,
							internalAsyncResult.Count);

						internalAsyncResult.SetComplete(bytesReadIntoUserBuffer);
					}
				}
			}
			catch (Exception ex)
			{
				internalAsyncResult.SetComplete(ex);
			}
		}

		public override int EndRead(IAsyncResult asyncResult)
		{
			if (disposed)
				return 0;

			var internalAsyncResult = asyncResult as InternalAsyncResult;
			if (internalAsyncResult == null)
			{
				throw new ArgumentException("AsyncResult was not obtained via BeginRead", "asyncResult");
			}
			// Check to see if the operation is complete, if not -- let's wait for it
			if (!internalAsyncResult.IsCompleted)
			{
				if (!internalAsyncResult.AsyncWaitHandle.WaitOne(WaitTimeOut, false))
				{
					throw new IOException("Failed to complete read operation");
				}
			}

			// If we completed with an error, throw the exceptions
			if (internalAsyncResult.CompletedWithError)
			{
				throw new Exception("AsyncException", internalAsyncResult.AsyncException);
			}

			// Success, return the bytes read
			return internalAsyncResult.BytesRead;
		}

		//!! - not implmenting blocking Write, use BeginWrite with no callback
		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotImplementedException();
		}

		public override IAsyncResult BeginWrite(
			byte[] buffer,
			int offset,
			int count,
			AsyncCallback asyncCallback,
			object asyncState)
		{
			if (disposed)
				return null;

			if (buffer == null)
			{
				throw new ArgumentNullException("buffer", "buffer can't be null");
			}
			if (offset < 0)
			{
				throw new ArgumentOutOfRangeException("offset", "offset less than 0");
			}
			if (offset > buffer.Length)
			{
				throw new ArgumentOutOfRangeException("offset", "offset must be less than buffer length");
			}
			if (count < 0)
			{
				throw new ArgumentOutOfRangeException("count", "count less than 0");
			}
			if (count > (buffer.Length - offset))
			{
				throw new ArgumentOutOfRangeException("count", "count is greater than buffer length - offset");
			}

			bool proceedAfterHandshake = count != 0;

			var asyncResult = new InternalAsyncResult(
				asyncCallback, 
				asyncState, 
				buffer, 
				offset, 
				count, 
				true, 
				proceedAfterHandshake);

			if (NeedHandshake)
			{
				// Start the handshake
				BeginHandshake(asyncResult);
			}
			else
			{
				InternalBeginWrite(asyncResult);
			}

			return asyncResult;
		}

		private void InternalBeginWrite(InternalAsyncResult asyncResult)
		{
			if (disposed)
				return;

			var new_buffer = asyncResult.Buffer;

			if (asyncResult.Offset != 0 && asyncResult.Count != 0)
			{
				new_buffer = new byte[asyncResult.Count];
				Array.Copy(asyncResult.Buffer, asyncResult.Offset, new_buffer, 0, asyncResult.Count);
			}

			// Only write to the SSL object if we have data
			if (asyncResult.Count != 0)
			{
				var bytesWritten = ssl.Write(new_buffer, asyncResult.Count);
				if (bytesWritten < 0)
				{
					var lastError = ssl.GetError(bytesWritten);
					if (lastError == SslError.SSL_ERROR_WANT_READ)
					{
						//!!TODO - Log - unexpected renogiation request
					}
					throw new OpenSslException();
				}
			}

			var bytesPending = write_bio.BytesPending;
			if (bytesPending > 0)
			{
				var buf = write_bio.ReadBytes((int)bytesPending);
				if (buf.Count > 0)
				{
					innerStream.BeginWrite(
						buf.Array, 0, buf.Count, 
						InternalWriteCallback, 
						asyncResult
					);
				}
			}
		}

		private void InternalWriteCallback(IAsyncResult asyncResult)
		{
			var internalAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;

			try
			{
				innerStream.EndWrite(asyncResult);
				internalAsyncResult.SetComplete();
			}
			catch (Exception ex)
			{
				internalAsyncResult.SetComplete(ex);
			}
		}

		public override void EndWrite(IAsyncResult asyncResult)
		{
			if (disposed)
				return;

			var internalAsyncResult = asyncResult as InternalAsyncResult;

			if (internalAsyncResult == null)
			{
				throw new ArgumentException("AsyncResult object was not obtained from SslStream.BeginWrite", "asyncResult");
			}

			if (!internalAsyncResult.IsCompleted)
			{
				if (!internalAsyncResult.AsyncWaitHandle.WaitOne(WaitTimeOut, false))
				{
					throw new IOException("Failed to complete the Write operation");
				}
			}

			if (internalAsyncResult.CompletedWithError)
			{
				throw new Exception("AsyncException", internalAsyncResult.AsyncException);
			}
		}

		private void RenegotiationWriteCallback(IAsyncResult asyncResult)
		{
			var readwriteAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;

			innerStream.EndWrite(asyncResult);

			// Now start the read with the original asyncresult, as the ssl.Read will handle the renegoiation
			InternalBeginRead(readwriteAsyncResult);
		}

		private IAsyncResult BeginHandshake(InternalAsyncResult readwriteAsyncResult)
		{
			if (disposed)
				return null;
			//!!
			// Move the handshake state to the next state
			//if (handShakeState == HandshakeState.Renegotiate)
			//{
			//    handShakeState = HandshakeState.RenegotiateInProcess;
			//}
			//else
			if (handShakeState != HandshakeState.Renegotiate)
			{
				handShakeState = HandshakeState.InProcess;
			}

			// Wrap the read/write InternalAsyncResult in the Handshake InternalAsyncResult instance
			var handshakeAsyncResult = new InternalAsyncResult(
				                           AsyncHandshakeComplete, 
				                           readwriteAsyncResult, 
				                           null, 
				                           0, 
				                           0, 
				                           readwriteAsyncResult.IsWriteOperation, 
				                           readwriteAsyncResult.ContinueAfterHandshake);

			if (ProcessHandshake())
			{
				handShakeState = HandshakeState.Complete;
				handshakeAsyncResult.SetComplete();
			}
			else
			{
				//!! if (readwriteAsyncResult.IsWriteOperation)
				if (write_bio.BytesPending > 0)
				{
					handshakeAsyncResult.IsWriteOperation = true;
					BeginWrite(new byte[0], 0, 0, AsyncHandshakeCallback, handshakeAsyncResult);
				}
				else
				{
					handshakeAsyncResult.IsWriteOperation = false;
					BeginRead(new byte[0], 0, 0, AsyncHandshakeCallback, handshakeAsyncResult);
				}
			}
			return handshakeAsyncResult;
		}

		private void AsyncHandshakeCallback(IAsyncResult asyncResult)
		{
			// Get the handshake internal result instance
			var internalAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;
			var bytesRead = 0;

			if (internalAsyncResult.IsWriteOperation)
			{
				EndWrite(asyncResult);
				// Check to see if the handshake is complete (this could have been
				// the last response packet from the server.  If so, we want to finalize
				// the async operation and call the HandshakeComplete callback
				if (handShakeState == HandshakeState.Complete)
				{
					internalAsyncResult.SetComplete();
					return;
				}
				// Check to see if we saved an exception from the last Handshake process call
				// the if the client gets an error code, it needs to send the alert, and then
				// throw the exception here.
				if (handshakeException != null)
				{
					internalAsyncResult.SetComplete(handshakeException);
					return;
				}
				// We wrote out the handshake data, now read to get the response
				internalAsyncResult.IsWriteOperation = false;
				BeginRead(new byte[0], 0, 0,  AsyncHandshakeCallback, internalAsyncResult);
			}
			else
			{
				try
				{
					bytesRead = EndRead(asyncResult);
					if (bytesRead > 0)
					{
						if (ProcessHandshake())
						{
							handShakeState = HandshakeState.Complete;
							// We have completed the handshake, but need to send the
							// last response packet.
							if (write_bio.BytesPending > 0)
							{
								internalAsyncResult.IsWriteOperation = true;
								BeginWrite(new byte[0], 0, 0, AsyncHandshakeCallback, internalAsyncResult);
							}
							else
							{
								internalAsyncResult.SetComplete();
								return;
							}
						}
						else
						{
							// Not complete with the handshake yet, write the handshake packet out if available
							// or poll for additional data
							if (write_bio.BytesPending > 0)
							{
								internalAsyncResult.IsWriteOperation = true;
								BeginWrite(new byte[0], 0, 0, AsyncHandshakeCallback, internalAsyncResult);
							}
							else
							{
								internalAsyncResult.IsWriteOperation = false;
								BeginRead(new byte[0], 0, 0, AsyncHandshakeCallback, internalAsyncResult);
							}
						}
					}
					else
					{
						// Read read 0 bytes, the remote socket has been closed, so complete the operation
						internalAsyncResult.SetComplete(new IOException("The remote stream has been closed"));
					}
				}
				catch (Exception ex)
				{
					internalAsyncResult.SetComplete(ex);
				}
			}
		}

		private void AsyncHandshakeComplete(IAsyncResult asyncResult)
		{
			if (disposed)
				return;

			EndHandshake(asyncResult);
		}

		private void EndHandshake(IAsyncResult asyncResult)
		{
			if (disposed)
				return;

			var handshakeAsyncResult = asyncResult as InternalAsyncResult;
			var readwriteAsyncResult = asyncResult.AsyncState as InternalAsyncResult;

			if (!handshakeAsyncResult.IsCompleted)
			{
				handshakeAsyncResult.AsyncWaitHandle.WaitOne(WaitTimeOut, false);
			}
			if (handshakeAsyncResult.CompletedWithError)
			{
				// if there's a handshake error, pass it to the read asyncresult instance
				readwriteAsyncResult.SetComplete(handshakeAsyncResult.AsyncException);
				return;
			}
			if (readwriteAsyncResult.ContinueAfterHandshake)
			{
				// We should continue the read/write operation since the handshake is complete
				if (readwriteAsyncResult.IsWriteOperation)
				{
					InternalBeginWrite(readwriteAsyncResult);
				}
				else
				{
					InternalBeginRead(readwriteAsyncResult);
				}
			}
			else
			{
				// If we aren't continuing, we're done
				readwriteAsyncResult.SetComplete();
			}
		}

		public override void Close()
		{
			if (disposed)
				return;

			if (ssl != null)
			{
				ssl.Dispose();
				ssl = null;
			}
			if (sslContext != null)
			{
				sslContext.Dispose();
				sslContext = null;
			}

			base.Close();
			Dispose();
		}

		#endregion

		/// <summary>
		/// Renegotiate session keys - calls SSL_renegotiate
		/// </summary>
		public void Renegotiate()
		{
			if (ssl != null)
			{
				// Call the SSL_renegotiate to reset the SSL object state
				// to start handshake
				Native.ExpectSuccess(Native.SSL_renegotiate(ssl.Handle));
				handShakeState = HandshakeState.Renegotiate;
			}
		}

		#region IDisposable Members

		protected override void Dispose(bool disposing)
		{
			if (disposed)
			{
				return;
			}

			disposed = true;
			base.Dispose();
		}

		#endregion
	}
}
