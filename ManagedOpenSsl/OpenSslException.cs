using System;
using System.Text;
using System.Collections.Generic;

namespace OpenSSL
{
	class OpenSslException : Exception
	{
		public OpenSslException()
			: base(GetErrorMessage())
		{
		}

		public static string GetErrorMessage()
		{
			System.Collections.Generic.Stack<uint> errors = new System.Collections.Generic.Stack<uint>(); 
			while (true)
			{
				uint err = Native.ERR_get_error();
				if (err == 0)
					break;

				errors.Push(err);
			}

			StringBuilder sb = new StringBuilder();
			bool isFirst = true;
			while (errors.Count != 0)
			{
				uint err = errors.Pop();
				byte[] buf = new byte[1024];
				uint len = Native.ERR_error_string_n(err, buf, buf.Length);
				if (isFirst)
					isFirst = false;
				else
					sb.Append("\n");
				sb.Append(Encoding.ASCII.GetString(buf, 0, (int)len));
			}

			return sb.ToString();
		}

		//public uint ErrorCode
		//{
		//    get { return this.err; }
		//}

		//public string Library
		//{
		//    get { return Native.PtrToStringAnsi(Native.ERR_lib_error_string(this.err)); }
		//}

		//public string Reason
		//{
		//    get { return Native.PtrToStringAnsi(Native.ERR_reason_error_string(this.err)); }
		//}

		//public string Function
		//{
		//    get { return Native.PtrToStringAnsi(Native.ERR_func_error_string(this.err)); }
		//}
	}
}
