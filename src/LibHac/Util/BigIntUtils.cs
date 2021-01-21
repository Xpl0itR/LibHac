using System;
using System.Numerics;

namespace LibHac.Util
{
    public static class BigIntUtils
    {
        public static BigInteger GetBigInteger(this ReadOnlySpan<byte> bytes)
        {
            byte[] signPadded = new byte[bytes.Length + 1];
            bytes.CopyTo(signPadded.AsSpan(1));
            Array.Reverse(signPadded);
            return new BigInteger(signPadded);
        }

        public static byte[] GetBytes(this BigInteger value, int size)
        {
            byte[] bytes = value.ToByteArray();

            if (size == -1)
            {
                size = bytes.Length;
            }

            if (bytes.Length > size + 1)
            {
                throw new InvalidOperationException($"Cannot squeeze value {value} to {size} bytes from {bytes.Length}.");
            }

            if (bytes.Length == size + 1 && bytes[bytes.Length - 1] != 0)
            {
                throw new InvalidOperationException($"Cannot squeeze value {value} to {size} bytes from {bytes.Length}.");
            }

            Array.Resize(ref bytes, size);
            Array.Reverse(bytes);
            return bytes;
        }
    }
}