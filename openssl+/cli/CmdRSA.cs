using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.CLI
{
	class CmdRSA : ICommand
	{
		void Usage()
		{
			Console.WriteLine(
@"rsa [options] <infile >outfile
where options are
 -inform arg     input format - one of DER NET PEM
 -outform arg    output format - one of DER NET PEM
 -in arg         input file
 -sgckey         Use IIS SGC key format
 -passin arg     input file pass phrase source
 -out arg        output file
 -passout arg    output file pass phrase source
 -des            encrypt PEM output with cbc des
 -des3           encrypt PEM output with ede cbc des using 168 bit key
 -aes128, -aes192, -aes256
                 encrypt PEM output with cbc aes
 -text           print the key in text
 -noout          don't print key out
 -modulus        print the RSA key modulus
 -check          verify key consistency
 -pubin          expect a public key in input file
 -pubout         output a public key
 -engine e       use engine e, possibly a hardware device.");
		}

		#region ICommand Members

		public void Execute(string[] args)
		{
			Usage();
		}

		#endregion
	}
}
