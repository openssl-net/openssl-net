using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL;

namespace OpenSSL.CLI
{
	class CmdVersion : ICommand
	{
		OptionParser options = new OptionParser();

		public CmdVersion()
		{
			options.AddOption("-a", new Option("all", false));
			options.AddOption("-v", new Option("version", false));
			options.AddOption("-b", new Option("date", false));
			options.AddOption("-o", new Option("options", false));
			options.AddOption("-f", new Option("cflags", false));
			options.AddOption("-p", new Option("platform", false));
			options.AddOption("-d", new Option("dir", false));
		}

		void Usage()
		{
			Console.Error.WriteLine(
@"version [options]
where options are
 -a    all
 -v    version
 -b    build date
 -o    options
 -f    cflags
 -p    platform
 -d    build directory
");
		}
		#region ICommand Members

		public void Execute(string[] args)
		{
			try
			{
				options.ParseArguments(args);
			}
			catch (Exception)
			{
				Usage();
				return;
			}

			bool version = false;
			bool date = false;
			bool platform = false;
			bool cflags = false;
			bool dir = false;
			bool opts = false;

			if (options.IsSet("version") || args.Length == 1) version = true;
			if (options.IsSet("date")) date = true;
			if (options.IsSet("platform")) platform = true;
			if (options.IsSet("cflags")) cflags = true;
			if (options.IsSet("dir")) dir = true;
			if (options.IsSet("options")) opts = true;
			if (options.IsSet("all")) version = date = platform = cflags = dir = opts = true;

			if (version) Console.WriteLine(Version.GetText(Version.Format.Text));
			if (date) Console.WriteLine(Version.GetText(Version.Format.BuildDate));
			if (platform) Console.WriteLine(Version.GetText(Version.Format.Platform));
			if (opts)
			{
				Console.WriteLine("options:  {0} {1} {2} {3} {4} {5}",
					BigNumber.Options,
					Crypto.MD2_Options,
					Crypto.RC4_Options,
					Crypto.DES_Options,
					Crypto.Idea_Options,
					Crypto.Blowfish_Options);
			}
			if (cflags) Console.WriteLine(Version.GetText(Version.Format.CompilerFlags));
			if (dir) Console.WriteLine(Version.GetText(Version.Format.BuildDirectory));
		}

		#endregion
	}
}
