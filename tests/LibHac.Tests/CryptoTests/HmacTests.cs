using System;
using System.Security.Cryptography;
using LibHac.Crypto;
using LibHac.Util;
using Xunit;

namespace LibHac.Tests.CryptoTests
{
    public static class HmacTests // Test vectors from https://tools.ietf.org/html/rfc4231#section-4
    {
        private static readonly MD5 Md5 = MD5.Create();
        private static readonly SHA1 Sha1 = SHA1.Create();
        private static readonly SHA256 Sha256 = SHA256.Create();
        private static readonly SHA384 Sha384 = SHA384.Create();
        private static readonly SHA512 Sha512 = SHA512.Create();

        public static readonly TheoryData<TestData> HmacTestVectors1 = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Md5,
                Expected = "5ccec34ea9656392457fa1ac27f08fbc".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "b617318655057264e28bc0b6fb378c8ef146be00".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854".ToBytes()
            }
        };

        public static readonly TheoryData<TestData> HmacWithKeyShorterThanOutputTestVectors = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Md5,
                Expected = "750c783e6ab0b503eaa86e310a5db738".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737".ToBytes()
            }
        };

        public static readonly TheoryData<TestData> HmacWithKeyAndDataTotallingMoreThan64BytesTestVectors = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Md5,
                Expected = "697eaf0aca3a3aea3a75164746ffaa79".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "4c9007f4026250c6bc8414f9bf50c86c2d7235da".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd".ToBytes()
            }
        };

        public static readonly TheoryData<TestData> HmacWithTruncationTo128BitsTestVectors = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Md5,
                Expected = "951726cea438b8e106e43b3d87a19c8e".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "4c1a03424b55e07fe7f27be1d58bb932".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "a3b6167473100ee06e0c796c2955552b".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "3abf34c3503b2a23a46efc619baef897".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "415fad6271580a531d4179bc891d87a6".ToBytes()
            }
        };

        public static readonly TheoryData<TestData> HmacWithKeyLargerThan128BytesTestVectors = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Md5,
                Expected = "bfecaf4efff90a3a668f3922fec3762d".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "90d0dace1c1bdc957339307803160335bde6df2b".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598".ToBytes()
            }
        };

        public static readonly TheoryData<TestData> HmacWithKeyAndDataLargerThan128BytesTestVectors = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Md5,
                Expected = "09b8ae7b15adbbb243aca3491b51512b".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "217e44bb08b6e06a2d6c30f3cb9f537f97c63356".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58".ToBytes()
            }
        };

        [Theory, MemberData(nameof(HmacTestVectors1))]
        public static void HmacTestCase1(TestData testData)
        {
            byte[] key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".ToBytes();
            byte[] data = "4869205468657265".ToBytes();

            HmacTest(key, data, testData);
        }

        [Theory, MemberData(nameof(HmacWithKeyShorterThanOutputTestVectors))]
        public static void HmacWithKeyShorterThanOutput(TestData testData)
        {
            byte[] key = "4a656665".ToBytes();
            byte[] data = "7768617420646f2079612077616e7420666f72206e6f7468696e673f".ToBytes();

            HmacTest(key, data, testData);
        }

        [Theory, MemberData(nameof(HmacWithKeyAndDataTotallingMoreThan64BytesTestVectors))]
        public static void HmacWithKeyAndDataTotallingMoreThan64Bytes(TestData testData)
        {
            byte[] key = "0102030405060708090a0b0c0d0e0f10111213141516171819".ToBytes();
            byte[] data = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".ToBytes();

            HmacTest(key, data, testData);
        }

        [Theory, MemberData(nameof(HmacWithTruncationTo128BitsTestVectors))]
        public static void HmacWithTruncationTo128Bits(TestData testData)
        {
            byte[] key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c".ToBytes();
            byte[] data = "546573742057697468205472756e636174696f6e".ToBytes();

            HmacTest(key, data, testData, 16);
        }

        [Theory, MemberData(nameof(HmacWithKeyLargerThan128BytesTestVectors))]
        public static void HmacWithKeyLargerThan128Bytes(TestData testData)
        {
            byte[] key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".ToBytes();
            byte[] data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374".ToBytes();

            HmacTest(key, data, testData);
        }

        [Theory, MemberData(nameof(HmacWithKeyAndDataLargerThan128BytesTestVectors))]
        public static void HmacWithKeyAndDataLargerThan128Bytes(TestData testData)
        {
            byte[] key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".ToBytes();
            byte[] data = "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e".ToBytes();

            HmacTest(key, data, testData);
        }

        private static void HmacTest(byte[] key, byte[] data, TestData testData, int truncateToBytes = 0)
        {
            Hmac hmac = new Hmac(key, testData.HashAlgorithm);
            byte[] actual = new byte[hmac.HashSize];
            hmac.ComputeHash(data, actual);

            if (truncateToBytes > 0)
            {
                Array.Resize(ref actual, truncateToBytes);
            }

            Assert.Equal(testData.Expected, actual);
        }

        public struct TestData
        {
            public HashAlgorithm HashAlgorithm;
            public byte[] Expected;
        }
    }
}