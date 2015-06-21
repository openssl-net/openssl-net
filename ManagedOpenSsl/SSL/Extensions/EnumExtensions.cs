using System;

namespace OpenSSL
{
	/// <summary>
	/// Enum extensions.
	/// </summary>
    public static class EnumExtensions
    {
		/// <summary>
		/// Determines if has flag the specified value flag.
		/// </summary>
		/// <returns><c>true</c> if has flag the specified value flag; otherwise, <c>false</c>.</returns>
		/// <param name="value">Value.</param>
		/// <param name="flag">Flag.</param>
		public static bool HasFlag(Enum value, Enum flag)
		{
			var longValue = Convert.ToInt64(value);
			var longFlag = Convert.ToInt64(flag);
			return (longValue & longFlag) == longFlag;
		}
    }
}

