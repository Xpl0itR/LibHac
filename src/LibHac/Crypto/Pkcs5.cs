using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace LibHac.Crypto
{
    public static class Pkcs5
    {
        /// <summary>
        /// Derive a cryptographically secure key using Password-Based Key Derivation Function 2
        /// </summary>
        /// <param name="derivedKey">The Derived key (DK) produced by this function</param>
        /// <param name="password">Password (P) to be used as a seed by the Pseudo-Random Function</param>
        /// <param name="salt">Salt (S) to be used as part of the input data of the first hash of every block</param>
        /// <param name="iterations">Number of rounds (c) of hashing per block</param>
        /// <param name="pseudoRandomFunction">Pseudo-Random Function (PRF) used to hash the blocks</param>
        /// <remarks>https://tools.ietf.org/html/rfc2898#section-5.2</remarks>
        public static void Pbkdf2(Span<byte> derivedKey, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, HashAlgorithm pseudoRandomFunction)
        {
            Hmac hmac = new Hmac(password, pseudoRandomFunction);

            int dkLen = derivedKey.Length;
            int hLen = hmac.HashSize;
            
            if (dkLen > (2 ^ 32 - 1) * hLen)
            {
                throw new Exception("derived key too long");
            }
            
            int blocks = dkLen / hLen + (dkLen % hLen == 0 ? 0 : 1); // Number of hLen-octet blocks in the derived key, rounding up
            int remain = dkLen        - (blocks - 1) * hLen;         // Number of octets in the last block
            
            Span<byte> saltFull = stackalloc byte[salt.Length + sizeof(uint)]; // S || BigEndian-UInt (index)
            Span<byte> hashed = stackalloc byte[hLen];                         // U_c
            
            salt.CopyTo(saltFull);
            Span<byte> indexPart = saltFull.Slice(salt.Length);

            for (uint index = 1; index <= blocks; index++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(indexPart, index);
                hmac.ComputeHash(saltFull, hashed); // U_1 = PRF (P, S || BigEndian-UInt (index))
                
                Span<byte> block = derivedKey.Slice((int)(index - 1) * hLen); // T_index

                if (index == blocks)
                {
                    hashed.Slice(0, remain).CopyTo(block);
                }
                else
                {
                    hashed.CopyTo(block);
                }

                for (int i = 1; i < iterations; i++) // T_index = U_1 \xor U_2 \xor ... \xor U_c
                {
                    hmac.ComputeHash(hashed, hashed); // U_c = PRF (P, U_{c-1})

                    Utilities.XorArrays(block, hashed);
                }
            }
        }
    }
}