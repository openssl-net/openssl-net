using System;
using System.Collections.Generic;
using System.Text;
using System.Reflection;

namespace OpenSSL.CLI
{
	class Option
	{
		private string name;
		private object value;

		public string Name
		{
			get { return this.name; }
		}

		public object Value
		{
			get { return this.value; }
			set { this.value = value; }
		}

		public Option(string name, object value)
		{
			this.name = name;
			this.value = value;
		}
	}

	class OptionParser
	{
		Dictionary<string, Option> optionsByKeyword = new Dictionary<string,Option>();
		Dictionary<string, Option> optionsByName = new Dictionary<string, Option>();
		List<string> args = new List<string>();

		public OptionParser()
		{
		}

		public void AddOption(string keyword, Option option)
		{
			this.optionsByKeyword.Add(keyword, option);
			this.optionsByName.Add(option.Name, option);
		}

		public void ParseArguments(string[] args)
		{
			for (int i = 1; i < args.Length; i++)
			{
				if (!args[i].StartsWith("-"))
				{
					this.args.Add(args[i]);
					continue;
				}

				if (!this.optionsByKeyword.ContainsKey(args[i]))
					throw new ArgumentOutOfRangeException(args[i], "Option not defined");

				Option option = this.optionsByKeyword[args[i]];
				if (option.Value.GetType() == typeof(bool))
					option.Value = true;
				else if (option.Value.GetType() == typeof(string))
					option.Value = args[++i];
			}
		}

		public List<string> Arguments
		{
			get { return this.args; }
		}

		public object this[string name]
		{
			get { return this.optionsByName[name].Value; }
		}

		public string GetString(string name)
		{
			return (string)this.optionsByName[name].Value; 
		}

		public bool IsSet(string name)
		{
			return (bool)this.optionsByName[name].Value;
		}
	}
}
