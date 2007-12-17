using System;
using System.Text;
using System.Collections.Generic;

namespace OpenSSL
{
	/// <summary>
	/// This is a struct that contains a uint for the native openssl error code.
	/// It provides helper methods to convert this error code into strings.
	/// </summary>
	public struct OpenSslError
	{
		private uint err;

		/// <summary>
		/// Constructs an OpenSslError object.
		/// </summary>
		/// <param name="err">The native error code</param>
		public OpenSslError(uint err)
		{
			this.err = err;
		}

		/// <summary>
		/// Returns the native error code
		/// </summary>
		public uint ErrorCode
		{
			get { return this.err; }
		}

		/// <summary>
		/// Returns the result of ERR_lib_error_string()
		/// </summary>
		public string Library
		{
			get { return Native.PtrToStringAnsi(Native.ERR_lib_error_string(this.err), false); }
		}

		/// <summary>
		/// Returns the results of ERR_reason_error_string()
		/// </summary>
		public string Reason
		{
			get { return Native.PtrToStringAnsi(Native.ERR_reason_error_string(this.err), false); }
		}

		/// <summary>
		/// Returns the results of ERR_func_error_string()
		/// </summary>
		public string Function
		{
			get { return Native.PtrToStringAnsi(Native.ERR_func_error_string(this.err), false); }
		}

		/// <summary>
		/// Returns the results of ERR_error_string_n()
		/// </summary>
		public string Message
		{
			get
			{
				byte[] buf = new byte[1024];
				uint len = Native.ERR_error_string_n(err, buf, buf.Length);
				return Encoding.ASCII.GetString(buf, 0, (int)len);
			}
		}
	}

	/// <summary>
	/// Exception class to provide OpenSSL specific information when errors occur.
	/// </summary>
	public class OpenSslException : Exception
	{
		private List<OpenSslError> errors = new List<OpenSslError>();

		private OpenSslException(List<OpenSslError> context)
			: base(GetErrorMessage(context))
		{
			this.errors = context;
		}

		/// <summary>
		/// When this class is instantiated, GetErrorMessage() is called automatically.
		/// This will call ERR_get_error() on the native openssl interface, once for every
		/// error that is in the current context. The exception message is the concatination
		/// of each of these errors turned into strings using ERR_error_string_n().
		/// </summary>
		public OpenSslException()
			: this(GetCurrentContext())
		{
		}

		private static List<OpenSslError> GetCurrentContext()
		{
			List<OpenSslError> ret = new List<OpenSslError>();
			while (true)
			{
				uint err = Native.ERR_get_error();
				if (err == 0)
					break;

				ret.Add(new OpenSslError(err));
			}
			return ret;
		}

		private static string GetErrorMessage(List<OpenSslError> context)
		{
			StringBuilder sb = new StringBuilder();
			bool isFirst = true;
			foreach (OpenSslError err in context)
			{
				if (isFirst)
					isFirst = false;
				else
					sb.Append("\n");
				sb.Append(err.Message);
			}

			return sb.ToString();
		}

		/// <summary>
		/// Returns the list of errors associated with this exception.
		/// </summary>
		public List<OpenSslError> Errors
		{
			get { return this.errors; }
		}
	}
}
