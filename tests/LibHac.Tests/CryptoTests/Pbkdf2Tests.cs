using System.Security.Cryptography;
using System.Text;
using LibHac.Crypto;
using LibHac.Util;
using Xunit;

namespace LibHac.Tests.CryptoTests
{
    public static class Pbkdf2Tests // Test vectors from https://tools.ietf.org/html/rfc6070#section-2
    {
        private static readonly SHA1 Sha1 = SHA1.Create();
        private static readonly SHA256 Sha256 = SHA256.Create();
        private static readonly SHA384 Sha384 = SHA384.Create();
        private static readonly SHA512 Sha512 = SHA512.Create();

        public static readonly TheoryData<TestData> Pbkdf2TestVectors1 = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "0c60c80f961f0e71f3a9b524af6012062fe037a6".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "120fb6cffcf8b32c43e7225256c4f837a86548c9".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "c0e14f06e49e32d73f9f52ddf1d0c5c719160923".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "867f70cf1ade02cff3752599a3a53dc4af34c7a6".ToBytes()
            }
        };

        public static readonly TheoryData<TestData> Pbkdf2TestVectors2 = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "ae4d0c95af6b46d32d0adff928f06dd02a303f8e".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "54f775c6d790f21930459162fc535dbf04a93918".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e".ToBytes()
            }
        };

        public static readonly TheoryData<TestData> Pbkdf2TestVectors3 = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "4b007901b765489abead49d926f721d065a429c1".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "c5e478d59288c841aa530db6845c4c8d962893a0".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "559726be38db125bc85ed7895f6e3cf574c7a01c".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "d197b1b33db0143e018b12f3d1d1479e6cdebdcc".ToBytes()
            }
        };

        public static readonly TheoryData<TestData> Pbkdf2TestVectors4 = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "819143ad66df9a552559b9e131c52ae6c5c1b0eed18f4d283b".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868".ToBytes()
            }
        };

        public static readonly TheoryData<TestData> Pbkdf2TestVectors5 = new TheoryData<TestData>
        {
            new TestData
            {
                HashAlgorithm = Sha1,
                Expected = "56fa6aa75548099dcc37d7f03425e0c3".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha256,
                Expected = "89b69d0516f829893c696226650a8687".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha384,
                Expected = "a3f00ac8657e095f8e0823d232fc60b3".ToBytes()
            },
            new TestData
            {
                HashAlgorithm = Sha512,
                Expected = "9d9e9c4cd21fe4be24d5b8244c759665".ToBytes()
            }
        };

        [Theory, MemberData(nameof(Pbkdf2TestVectors1))]
        public static void Pbkdf2Test1(TestData testData)
        {
            byte[] password = Encoding.ASCII.GetBytes("password");
            byte[] salt = Encoding.ASCII.GetBytes("salt");

            Pbkdf2Test(password, salt, 1, 20, testData);
        }

        [Theory, MemberData(nameof(Pbkdf2TestVectors2))]
        public static void Pbkdf2Test2(TestData testData)
        {
            byte[] password = Encoding.ASCII.GetBytes("password");
            byte[] salt = Encoding.ASCII.GetBytes("salt");

            Pbkdf2Test(password, salt, 2, 20, testData);
        }

        [Theory, MemberData(nameof(Pbkdf2TestVectors3))]
        public static void Pbkdf2Test3(TestData testData)
        {
            byte[] password = Encoding.ASCII.GetBytes("password");
            byte[] salt = Encoding.ASCII.GetBytes("salt");

            Pbkdf2Test(password, salt, 4096, 20, testData);
        }

        [Theory, MemberData(nameof(Pbkdf2TestVectors4))]
        public static void Pbkdf2Test4(TestData testData)
        {
            byte[] password = Encoding.ASCII.GetBytes("passwordPASSWORDpassword");
            byte[] salt = Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt");

            Pbkdf2Test(password, salt, 4096, 25, testData);
        }

        [Theory, MemberData(nameof(Pbkdf2TestVectors5))]
        public static void Pbkdf2Test5(TestData testData)
        {
            byte[] password = Encoding.ASCII.GetBytes("pass\0word");
            byte[] salt = Encoding.ASCII.GetBytes("sa\0lt");

            Pbkdf2Test(password, salt, 4096, 16, testData);
        }

        private static void Pbkdf2Test(byte[] password, byte[] salt, int iterations, int keyLength, TestData data)
        {
            byte[] actual = new byte[keyLength];
            Pkcs5.Pbkdf2(actual, password, salt, iterations, data.HashAlgorithm);
            Assert.Equal(data.Expected, actual);
        }

        public struct TestData
        {
            public HashAlgorithm HashAlgorithm;
            public byte[] Expected;
        }
    }
}