/** 
 *  Author: Nicholas Page
 *	This code is as-is and free to use for any purpose. No warranty is provided or implied.
 *	Most code is based off of the psuedocode on the Wikipedia article https://en.wikipedia.org/wiki/SHA-2#Pseudocode
 *	
 *	Inspiration:
 *	Me->ChatGPT: Can you write me C# code that performs the same operation as SHA-256?
 *	ChatGPT: [spits out code that utilized the ComputeSHA256Hash method from the .NET libraries]
 *	Me: No, I want you to recreate the SHA-256 algorithm in C#. Essentially what I am asking to see is source code that does all the hashing.
 *	ChatGPT: I apologize for the misunderstanding. However, it's important to note that implementing a cryptographic algorithm like SHA-256 from scratch is a complex and error-prone task. 
 *				It requires a deep understanding of cryptographic principles, bit manipulation [blah blah blah]
 *	Me: Try anyways.
 *	ChatGPT: Implementing a full SHA-256 algorithm from scratch is quite involved, and the code would be too long to fit in this response. 
 *				However, I can provide you with an overview of the steps involved in [blah blah blah]
 *	Me: I'll just write it myself.
 *	
 *	General information:
 *	A block refers to a fixed-size chunk of data that is processed together as a unit. It is typically a fundamental unit of data used in cryptographic algorithms and hashing functions.
 *	Here, the block size is defined as 64 bytes.
 *	
 *	When data is input to a cryptographic hash function, it is processed in blocks rather than individual bytes. 
 *	This allows for more efficient computation and enhances the security properties of the hash function. 
 *	If the input data does not fill a complete block, it is temporarily stored in the pending block until enough data is accumulated to fill a block, at which point the block is processed.
 *	
 *	Each block is processed independently using the specified cryptographic algorithm, and the output of each processed block is used as input for the subsequent block. 
 *	This iterative processing continues until all data has been processed, resulting in the final hash value.
 *	
 *	By dividing the data into blocks, the hash function can handle inputs of arbitrary length, ensuring consistent and secure hashing regardless of the size of the input data.
 *	
 *	Conversions are done using little Endian. Little-endian order is a byte ordering scheme used in computer architecture and data storage. 
 *	In a little-endian system, the least significant byte (the byte with the lowest memory address) of a multi-byte value is stored first, followed by the more significant bytes.
 *	
 */

using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;

namespace HashingAlgo
{
	public class SHA256
	{
		// Constants for SHA256 algorithm (from https://en.wikipedia.org/wiki/SHA-2)
		// Initialize array of round constants:
		//	(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
		private static readonly uint[] K = new uint[64] {
			0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
			0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
			0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
			0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
			0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
			0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
			0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
			0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
		};

		// Constants for SHA256 algorithm (from https://en.wikipedia.org/wiki/SHA-2)
		// Initialize hash values:
		//	(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
		private uint[] H = new uint[8] {
			0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
		};

		/// <summary>
		/// The pending block used to store data that does not fill a complete block.
		/// </summary>
		private byte[] pendingBlock = new byte[64];

		/// <summary>
		/// The offset within the pending block indicating the next available position to write data.
		/// </summary>
		private uint pendingBlockOffset = 0;

		/// <summary>
		/// The buffer used to store converted data from the pending block as an array of uints.
		/// </summary>
		private uint[] uintBuffer = new uint[16];

		/// <summary>
		/// The total number of bits processed by the hasher.
		/// </summary>
		private ulong bitsProcessed = 0;

		/// <summary>
		/// Indicates whether the hasher is closed or not.
		/// </summary>
		private bool closed = false;

		/// <summary>
		/// Processes a block of data using the SHA-256 algorithm and updates the hash value.
		/// </summary>
		/// <param name="message">The block of data to be processed as an array of 32-bit unsigned integers.</param>
		/// <remarks>
		/// This method follows the steps defined by the SHA-256 algorithm to process a single block of data.
		/// It prepares the message schedule, performs the hash computation loop, and updates the intermediate hash value.
		/// The hash value is stored in the internal state variable <c>H</c>.
		/// </remarks>
		private void ProcessBlock(uint[] message)
		{
			// Step 1: Prepare the message schedule (W[t])
			uint[] schedule = new uint[64];
			Array.Copy(message, schedule, 16); // Copy the first 16 elements from the message to the schedule

			// Extend the first 16 elements into the remaining 48 elements of the message schedule array
			for (int t = 16; t < 64; t++)
			{
				// Calculate the new schedule element based on previous elements
				uint sigma1Result = Sigma1(schedule[t - 2]);
				uint sigma0Result = Sigma0(schedule[t - 15]);
				uint scheduleElement = sigma1Result + schedule[t - 7] + sigma0Result + schedule[t - 16];
				schedule[t] = scheduleElement;
			}

			// Step 2: Initialize working variables with the current hash value
			uint a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

			// Step 3: Perform the main hash computation loop
			for (int t = 0; t < 64; ++t)
			{
				// Calculate intermediate values for the hash computation
				uint T1 = h + Sigma1(e) + Choose(e, f, g) + K[t] + schedule[t];
				uint T2 = Sigma0(a) + Majority(a, b, c);

				// Update working variables
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
			}

			// Step 4: Compute the intermediate hash value
			H[0] += a;
			H[1] += b;
			H[2] += c;
			H[3] += d;
			H[4] += e;
			H[5] += f;
			H[6] += g;
			H[7] += h;
		}

		public void AddData(byte[] data, uint offset, uint len)
		{
			// Check if the hasher is closed
			if (closed) throw new InvalidOperationException("Adding data to a closed hasher.");

			// If no data to add, return
			if (len == 0) return;

			// Update the total number of bits processed
			bitsProcessed += len * 8;

			// Process the data in chunks of 64 bytes (512 bits)
			while (len > 0)
			{
				uint amountToCopy;

				// Determine the amount of data to copy for the current iteration
				if (len < 64)
				{
					// If remaining data is less than 64 bytes, check if it fits within the pending block
					if (pendingBlockOffset + len > 64)
					{
						amountToCopy = 64 - pendingBlockOffset;
					}
					else
					{
						amountToCopy = len;
					}
				}
				else
				{
					// If more than 64 bytes remaining, copy a full block
					amountToCopy = 64 - pendingBlockOffset;
				}

				// Copy the data into the pending block
				Array.Copy(data, offset, pendingBlock, pendingBlockOffset, amountToCopy);

				// Update the counters and offsets
				len -= amountToCopy;
				offset += amountToCopy;
				pendingBlockOffset += amountToCopy;

				// If the pending block is full, process it
				if (pendingBlockOffset == 64)
				{
					// Convert the pending block to an array of uints
					ToUintArray(pendingBlock, uintBuffer);

					// Process the block
					ProcessBlock(uintBuffer);

					// Reset the pending block offset
					pendingBlockOffset = 0;
				}
			}
		}

		public ReadOnlyCollection<byte> GetHash()
		{
			return ToByteArray(GetHashUInt());
		}

		/// <summary>
		/// Retrieves the hash value as a read-only collection of uint values.
		/// </summary>
		/// <returns>The hash value as a read-only collection of uint values.</returns>
		public ReadOnlyCollection<uint> GetHashUInt()
		{
			if (closed == false)
			{
				ulong tempSize = bitsProcessed;

				// Step 1: Add the padding byte 0x80 to mark the start of padding
				AddData(new byte[1] { 0x80 }, 0, 1);

				// Calculate the available space in the pending block, which is the remaining capacity to fill it up to 64 bytes
				uint availableSpace = 64 - pendingBlockOffset;

				// If the available space is less than 8 bytes (the size needed to store the length),
				// it means there is not enough space for the length to fit in the pending block
				if (availableSpace < 8)
				{
					// Add an additional block (64 bytes) to accommodate the length value
					// This ensures that the length can always fit within a block even if the available space is insufficient
					availableSpace += 64;
				}

				// Step 2: Add additional padding bytes (0x00-initialized) to fill the remaining space
				byte[] padding = new byte[availableSpace];

				// Step 3: Insert the length of the original message in bits (as ulong) into the padding
				for (uint i = 1; i <= 8; i++)
				{
					// Calculate the index of the padding array to store the current byte
					// The bytes are stored in reverse order, starting from the end of the padding array
					// The index is calculated by subtracting the loop counter 'i' from the length of the padding array
					padding[padding.Length - i] = (byte)tempSize;

					// Right-shift the temporary size value by 8 bits to prepare for the next byte
					tempSize >>= 8;
				}

				// Step 4: Add the padding to the hash computation
				AddData(padding, 0u, (uint)padding.Length);

				// No further data will be added to the hash computation
				closed = true;
			}

			// Return the final hash value as a read-only collection
			return Array.AsReadOnly(H);
		}

		/// <summary>
		/// Converts an array of bytes to an array of unsigned integers.
		/// </summary>
		/// <param name="src">The source byte array to convert.</param>
		/// <param name="dest">The destination uint array to store the converted values.</param>
		/// <remarks>
		/// This method converts each sequence of 4 bytes from the source array to a single unsigned integer value,
		/// and stores the converted values in the destination array. The conversion is performed in little-endian order.
		/// The length of the destination array should be large enough to accommodate the converted values.
		/// </remarks>
		private static void ToUintArray(byte[] src, uint[] dest) => Enumerable.Range(0, dest.Length).ToList().ForEach(i => dest[i] = BitConverter.ToUInt32(src, i * 4));

		/// <summary>
		/// Converts a collection of uint values to a little-endian byte array.
		/// </summary>
		/// <param name="src">The collection of uint values.</param>
		/// <returns>A read-only collection of bytes in little-endian order.</returns>
		private static ReadOnlyCollection<byte> ToByteArray(ReadOnlyCollection<uint> src)
		{
			// Concatenate the individual bytes of each uint value in the source collection using LINQ
			byte[] dest = src.SelectMany(x => new[] { (byte)(x >> 24), (byte)(x >> 16), (byte)(x >> 8), (byte)x }).ToArray();

			// Return the resulting byte array as a read-only collection
			return Array.AsReadOnly(dest);
		}

		/// <summary>
		/// Computes the SHA-256 hash of a file provided as a stream.
		/// </summary>
		/// <param name="fs">The file stream.</param>
		/// <returns>The SHA-256 hash of the file.</returns>
		public static ReadOnlyCollection<byte> HashFile(Stream fs)
		{
			SHA256 sha = new SHA256();
			byte[] buffer = new byte[8196];
			uint bytesRead;

			while ((bytesRead = (uint)fs.Read(buffer, 0, buffer.Length)) != 0)
			{
				sha.AddData(buffer, 0, bytesRead);
			}

			return sha.GetHash();
		}

		/// <summary>
		/// Computes the SHA-256 hash of the specified input string.
		/// </summary>
		/// <param name="input">The input string to compute the hash for.</param>
		/// <returns>The SHA-256 hash of the input string.</returns>
		public static ReadOnlyCollection<byte> HashString(string input)
		{
			byte[] data = Encoding.UTF8.GetBytes(input);
			SHA256 hasher = new SHA256();
			hasher.AddData(data, 0, (uint)data.Length);
			ReadOnlyCollection<byte> hash = hasher.GetHash();
			return hash;
		}

		// Rotate carry
		private static uint RotateLeft(uint value, int bits)
		{
			// Shift the bits of the value to the left by the number of bits specified in bits
			// Then bitwise OR with the bits that were "shifted" off the left
			// Example: RotateLeft(0b_1001_0011, 2) == 0b_0100_1110
			return (value << bits) | (value >> (sizeof(uint) - bits));
		}

		// Rotate carry
		private static uint RotateRight(uint value, int bits)
		{
			// Shift the bits of the value to the right by the number of bits specified in bits
			// Then bitwise OR with the bits that were "shifted" off the right
			// Example: RotateRight(0b_1001_0011, 2) == 0b_1110_0100
			return (value >> bits) | (value << (sizeof(uint) - bits));
		}

		// The purpose of this method is to introduce non-linearity and provide diffusion (avalanche effect) in the hashing process.
		private static uint Choose(uint x, uint y, uint z)
		{
			// Perform a bitwise operation to select bits from y and z based on the bits of x.
			// Example: Choose(0b_1010_1010, 0b_1100_1100, 0b_1111_0000) == 0b_1100_1010
			return (x & y) ^ ((~x) & z);
		}

		// The purpose of this method is to introduce further confusion and diffusion on the input data.
		private static uint Majority(uint x, uint y, uint z)
		{
			// Perform a bitwise operation to select the most common bit from x, y, and z for each position.
			// Performs bitwise XOR operators between the results of the three operations to produce the final value.
			// Example: Majority(0b_1010_1010, 0b_1100_1100, 0b_1111_0000) == 0b_1110_1100
			return (x & y) ^ (x & z) ^ (y & z);
		}

		// Apply a series of bitwise rotations and XOR the operations to the input 'x', resulting in a transformed value.
		private static uint Sigma0(uint x)
		{
			// The numbers 2, 13, and 22 are not arbitrary choices but are carefully derived based on mathematical and cryptographic considerations
			return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22);
		}

		// Apply a series of bitwise rotations and XOR the operations to the input 'x', resulting in a transformed value.
		private static uint Sigma1(uint x)
		{
			// The numbers 6, 11, and 25 are not arbitrary choices but are carefully derived based on mathematical and cryptographic considerations
			return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25);
		}

		private static uint sigma0(uint x)
		{
			return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
		}

		private static uint sigma1(uint x)
		{
			return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
		}
	}
}
