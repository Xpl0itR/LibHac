using System;
using System.Security.Cryptography;
using LibHac.Common;

namespace LibHac.Crypto
{
    public readonly struct Hmac
    {
        public readonly int HashSize;
        
        private readonly HashAlgorithm _hashAlg;
        private readonly byte[] _innerKey;
        private readonly byte[] _outerKey;

        public Hmac(ReadOnlySpan<byte> key, HashAlgorithm hashAlg)
        {
            _hashAlg = hashAlg;
            _hashAlg.Initialize();

            int keyLength = key.Length;
            int blockSize = 64; // MD5, SHA1 and SHA256 use a block size of 64 bytes
            if (_hashAlg.HashSize == 384 || _hashAlg.HashSize == 512)
            {
                blockSize = 128; // SHA384 and SHA512 use a block size of 128 bytes
            }
            
            HashSize = _hashAlg.HashSize >> 3; // We want bytes not bits

            _innerKey = new byte[blockSize];
            _outerKey = new byte[blockSize];

            if (keyLength == blockSize)
            {
                Utilities.XorArray(_innerKey, key, 0x36);
                Utilities.XorArray(_outerKey, key, 0x5C);
            }
            else
            {
                Span<byte> paddedKey = stackalloc byte[blockSize];

                if (keyLength > blockSize)
                {
                    _hashAlg.TryComputeHash(key, paddedKey, out _);
                }
                else
                {
                    key.CopyTo(paddedKey);
                }

                Utilities.XorArray(_innerKey, paddedKey, 0x36);
                Utilities.XorArray(_outerKey, paddedKey, 0x5C);
            }
        }

        public void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            _hashAlg.TransformBlock(_innerKey, 0, _innerKey.Length, null, 0);
            
            using RentedArray<byte> tempArray = new RentedArray<byte>(source.Length);
            source.CopyTo(tempArray.Span);
            _hashAlg.TransformFinalBlock(tempArray.Array, 0, source.Length);
            byte[] innerHash = _hashAlg.Hash;

            _hashAlg.TransformBlock(_outerKey, 0, _outerKey.Length, null, 0);
            _hashAlg.TransformFinalBlock(innerHash, 0, HashSize);
            
            _hashAlg.Hash.CopyTo(destination);
        }
    }
}