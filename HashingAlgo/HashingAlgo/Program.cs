using System;
using System.Collections;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace HashingAlgo
{
	public class Program
	{
		public static void Main()
		{
			ReadOnlyCollection<byte> hash = SHA256.HashString("Hello, World!");
			ReadOnlyCollection<byte> hash2 = SHA256.HashString("Hello, world!");

			Console.WriteLine($"Hash of 'Hello, World!': {ConvertReadOnlyCollectionToHexString(hash) }");
			Console.WriteLine($"Hash of 'Hello, world!': {ConvertReadOnlyCollectionToHexString(hash2)}");
		}

		private static string ConvertReadOnlyCollectionToHexString(ReadOnlyCollection<byte> byteArray)
		{
			StringBuilder hexString = new StringBuilder(byteArray.Count * 2);

			foreach (byte b in byteArray)
			{
				hexString.Append(b.ToString("X2"));
			}

			return hexString.ToString();
		}
	}
}