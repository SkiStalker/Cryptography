using System.Collections;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography_Laba_1
{
    interface IKeyExpanding
    {
        byte[][] ExpandKey(byte[] key);
    }

    interface IRoundEncrypting
    {
        byte[] RoundEncrypt(byte[] data, byte[] roundKey);
    }

    interface IEncrypting
    {
        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);
        void SetKey(byte[] key);
    }

    class KeyExpander : IKeyExpanding
    {
        readonly byte[] suppressKeyTable = new byte[]
        {
            14, 17, 11, 24, 01, 05, 03, 28,
            15, 06, 21, 10, 23, 19, 12, 04,
            26, 08, 16, 07, 27, 20, 13, 02,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
        };

        private readonly byte[] removeEvenBitsTable = new byte[]
        {
            57, 49, 41, 33, 25, 17, 09, 01,
            58, 50, 42, 34, 26, 18, 10, 02,
            59, 51, 43, 35, 27, 19, 11, 03,
            60, 52, 44, 36, 63, 55, 47, 39,
            31, 23, 15, 07, 62, 54, 46, 37,
            30, 22, 14, 06, 61, 53, 45, 37,
            29, 21, 13, 05, 28, 20, 12, 04
        };

        byte[] LeftShift(byte[] key, int n)
        {
            byte[] result = new byte[key.Length];
            for (int i = 0; i < key.Length; i++)
            {
                result[i] = (byte)((key[i] << n) | (key[(i + 1) % key.Length] >> (8 - n)));
            }

            return result;
        }

        void GetKeyParts(byte[] key, byte[] leftPart, byte[] rightPart)
        {
            leftPart[0] = key[0];
            leftPart[1] = key[1];
            leftPart[2] = key[2];
            leftPart[3] = (byte)(key[3] & 0b11110000);

            rightPart[0] = (byte)(key[3] << 4 | key[4] >> 4);
            rightPart[1] = (byte)(key[4] << 4 | key[5] >> 4);
            rightPart[2] = (byte)(key[5] << 4 | key[6] >> 4);
            rightPart[3] = (byte)(key[6] << 4);
        }

        void MergeKeys(byte[] key, byte[] leftPart, byte[] rightPart)
        {
            key[0] = leftPart[0];
            key[1] = leftPart[1];
            key[2] = leftPart[2];
            key[3] = leftPart[3];

            key[3] |= (byte)(rightPart[0] >> 4);
            key[4] = (byte)(rightPart[0] << 4 | rightPart[1] >> 4);
            key[5] = (byte)(rightPart[1] << 4 | rightPart[2] >> 4);
            key[6] = (byte)(rightPart[2] << 4 | rightPart[3] >> 4);
        }
        
        public byte[][] ExpandKey(byte[] key)
        {
            byte[][] result = new byte[16][];
            DES.PBlock(ref key, removeEvenBitsTable);
            for (int i = 0; i < 16; i++)
            {
                int off = 0;
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    off = 1;
                }
                else
                {
                    off = 2;
                }

                byte[] leftPart = new byte[4];
                byte[] rightPart = new byte[4];
                GetKeyParts(key, leftPart, rightPart);

                var t = (Program.PrintBits(leftPart) + Program.PrintBits(rightPart) ).CompareTo(Program.PrintBits(key));
                
                leftPart = LeftShift(leftPart, off);
                leftPart[3] = (byte)(((leftPart[3] & (off | 1)) << 4) | leftPart[3] & 0b11110000);
                rightPart = LeftShift(rightPart, off);
                rightPart[3] = (byte)((rightPart[3] & (off | 1) << 4) | rightPart[3] & 0b11110000);
                MergeKeys(key, leftPart, rightPart);

                byte[] roundKey = new byte[key.Length];
                key.CopyTo(roundKey, 0);
                DES.PBlock(ref roundKey, suppressKeyTable);
                result[i] = roundKey;
            }

            return result;
        }
    }

    class RoundEncryptor : IRoundEncrypting
    {
        byte[][][] subTables = new byte[][][]
        {
            new byte[][]
            {
                new byte[] { 14, 04, 13, 01, 02, 15, 11, 08, 03, 10, 06, 12, 05, 09, 00, 07 },
                new byte[] { 00, 15, 07, 04, 14, 02, 13, 10, 03, 06, 12, 11, 09, 05, 03, 08 },
                new byte[] { 04, 01, 14, 07, 13, 06, 02, 11, 15, 12, 09, 07, 03, 10, 05, 00 },
                new byte[] { 15, 12, 08, 02, 04, 09, 01, 07, 05, 11, 03, 14, 10, 00, 06, 13 }
            },
            new byte[][]
            {
                new byte[] { 15, 01, 08, 14, 06, 11, 03, 04, 09, 07, 02, 13, 12, 00, 05, 10 },
                new byte[] { 03, 13, 04, 07, 15, 02, 08, 14, 12, 00, 01, 10, 06, 09, 11, 05 },
                new byte[] { 00, 14, 07, 11, 10, 04, 13, 01, 05, 08, 12, 06, 09, 03, 02, 15 },
                new byte[] { 13, 08, 10, 01, 03, 15, 04, 02, 11, 06, 07, 12, 00, 05, 14, 09 }
            },

            new byte[][]
            {
                new byte[] { 10, 00, 09, 14, 06, 03, 15, 05, 01, 13, 12, 07, 11, 04, 02, 08 },
                new byte[] { 13, 07, 00, 09, 03, 04, 06, 10, 02, 08, 05, 14, 12, 11, 15, 01 },
                new byte[] { 13, 06, 04, 09, 08, 15, 03, 00, 11, 01, 02, 12, 05, 10, 14, 07 },
                new byte[] { 01, 10, 13, 00, 06, 09, 08, 07, 04, 15, 14, 03, 11, 05, 02, 12 }
            },
            new byte[][]
            {
                new byte[] { 07, 13, 14, 03, 00, 06, 09, 10, 01, 02, 08, 05, 01, 12, 04, 15 },
                new byte[] { 13, 08, 11, 05, 06, 15, 00, 03, 04, 07, 02, 12, 01, 10, 14, 09 },
                new byte[] { 10, 06, 09, 00, 12, 11, 07, 13, 15, 01, 03, 14, 05, 02, 08, 04 },
                new byte[] { 03, 15, 00, 06, 10, 01, 13, 08, 09, 04, 05, 11, 12, 07, 02, 14 }
            },

            new byte[][]
            {
                new byte[] { 02, 12, 04, 01, 07, 10, 11, 06, 08, 05, 03, 15, 13, 00, 14, 09 },
                new byte[] { 14, 11, 02, 12, 04, 07, 13, 01, 05, 00, 15, 10, 03, 09, 08, 06 },
                new byte[] { 04, 02, 01, 11, 10, 13, 07, 08, 15, 09, 12, 05, 06, 03, 00, 14 },
                new byte[] { 11, 08, 12, 07, 01, 14, 02, 13, 06, 15, 00, 09, 10, 04, 05, 03 }
            },

            new byte[][]
            {
                new byte[] { 12, 01, 10, 15, 09, 02, 06, 08, 00, 13, 03, 04, 14, 07, 05, 11 },
                new byte[] { 10, 15, 04, 02, 07, 12, 09, 05, 06, 01, 13, 14, 00, 11, 03, 08 },
                new byte[] { 09, 14, 15, 05, 02, 08, 12, 03, 07, 00, 04, 10, 01, 13, 11, 06 },
                new byte[] { 04, 03, 02, 12, 09, 05, 15, 10, 11, 14, 01, 07, 10, 00, 08, 13 }
            },

            new byte[][]
            {
                new byte[] { 04, 11, 02, 14, 15, 00, 08, 13, 03, 12, 09, 07, 05, 10, 06, 01 },
                new byte[] { 13, 00, 11, 07, 04, 09, 01, 10, 14, 03, 05, 12, 02, 15, 08, 06 },
                new byte[] { 01, 04, 11, 13, 12, 03, 07, 14, 10, 15, 06, 08, 00, 05, 09, 02 },
                new byte[] { 06, 11, 13, 08, 01, 04, 10, 07, 09, 05, 00, 15, 14, 02, 03, 12 }
            },

            new byte[][]
            {
                new byte[] { 13, 02, 08, 04, 06, 15, 11, 01, 10, 09, 03, 14, 05, 00, 12, 07 },
                new byte[] { 01, 15, 13, 08, 10, 03, 07, 04, 12, 05, 06, 11, 10, 14, 09, 02 },
                new byte[] { 07, 11, 04, 01, 09, 12, 14, 02, 00, 06, 10, 10, 15, 03, 05, 08 },
                new byte[] { 02, 01, 14, 07, 04, 10, 05, 13, 15, 19, 09, 09, 03, 05, 06, 11 }
            }
        };


        byte[] expandBlock = new byte[]
        {
            32, 01, 02, 03, 04, 05,
            04, 05, 06, 07, 08, 09,
            08, 09, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 31, 31, 32, 01
        };

        byte[] straightPerBlock = new byte[]
        {
            16, 07, 20, 21, 29, 12, 28, 17,
            01, 15, 23, 26, 05, 18, 31, 10,
            02, 08, 24, 14, 32, 27, 03, 09,
            19, 13, 30, 06, 22, 11, 04, 25
        };

        public byte[] RoundEncrypt(byte[] data, byte[] roundKey)
        {
            byte[] res = new byte[data.Length];
            data.CopyTo(res, 0);
            byte[] rightPart = res.Take(new Range(4, 8)).ToArray();
            byte[] newRightPart = new byte[4];

            DES.PBlock(ref rightPart, expandBlock);

            for (int i = 0; i < 6; i++)
            {
                rightPart[i] ^= roundKey[i];
            }

            for (int i = 0; i < 8; i++)
            {
                byte tmp = DES.SBlock(rightPart, subTables[i], i);
                newRightPart[i / 2] |= (byte)(tmp << (4 * ((i + 1) % 2)));
            }

            DES.PBlock(ref newRightPart, straightPerBlock);

            for (int i = 0; i < 4; i++)
            {
                res[i] ^= newRightPart[i];
                (res[i], res[7 - i]) = (res[7 - i], res[i]);
            }

            return res;
        }
    }

    class Cipher
    {
        DES des;
        CryptRule cryptRule;
        byte[]? initVector;
        byte[] args;

        public enum CryptRule
        {
            ECB,
            CBC,
            CFB,
            OFB,
            CTR,
            RD,
            RDH
        }


        public static byte[] GenerateKey()
        {
            byte[] key = new byte[8];
            new Random().NextBytes(key);
            for (int i = 0; i < 8; i++)
            {
                int even = 0;
                for (int j = 1; j < 8; j++)
                {
                    even += (key[i] >> j) & 0b1;
                }

                key[i] = (byte)((key[i] & ~0b1) | even % 2);
            }

            return key;
        }

        public Cipher(byte[] key, CryptRule cryptRule, byte[]? initVector = null, params byte[] args)
        {
            des = new DES(key);
            this.cryptRule = cryptRule;
            this.initVector = initVector;
            this.args = args;
        }

        public void Encrypt(byte[] data, ref byte[] encryptData)
        {
            byte dataModLen = (byte)(8 - data.Length % 8);

            byte[] padding = new byte[dataModLen];
            for (int i = 0; i < dataModLen; i++)
            {
                padding[i] = dataModLen;
            }

            data = data.Concat(padding).ToArray();

            encryptData = new byte[data.Length];

            for (int i = 0; i < data.Length; i += 8)
            {
                switch (cryptRule)
                {
                    case CryptRule.ECB:
                    {
                        byte[] cryptData = des.DESEncrypt(data.Take(new Range(i, i + 8)).ToArray() ??
                                                          throw new NullReferenceException());
                        for (int j = 0; j < cryptData.Length; j++)
                        {
                            encryptData[j + i] = cryptData[j];
                        }

                        break;
                    }
                    default: throw new NotImplementedException();
                }
            }
        }

        public void Decrypt(byte[] data, ref byte[] decryptData)
        {
            decryptData = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 8)
            {
                switch (cryptRule)
                {
                    case CryptRule.ECB:
                    {
                        byte[] cryptData = des.DESDecrypt(data.Take(new Range(i, i + 8)).ToArray() ??
                                                          throw new NullReferenceException());
                        for (int j = 0; j < cryptData.Length; j++)
                        {
                            decryptData[j + i] = cryptData[j];
                        }

                        break;
                    }
                    default: throw new NotImplementedException();
                }
            }

            int paddingLen = decryptData.Last();
            decryptData = decryptData.Take(decryptData.Length - paddingLen).ToArray();
        }

        public void Encrypt(string inputFile, string outputFile)
        {
            byte[] data = File.ReadAllBytes(inputFile);
            byte[] res = Array.Empty<byte>();
            Encrypt(data, ref res);
            File.WriteAllBytes(outputFile, res);
        }

        public void Decrypt(string inputFile, string outputFile)
        {
            byte[] data = File.ReadAllBytes(inputFile);
            byte[] res = Array.Empty<byte>();
            Decrypt(data, ref res);
            File.WriteAllBytes(outputFile, res);
        }
    }

    class FeistelNetwork : IEncrypting
    {
        byte[][] roundKeys = Array.Empty<byte[]>();

        private IKeyExpanding keyExpander;
        private IRoundEncrypting roundEncryptor;

        public FeistelNetwork(IKeyExpanding keyExpander, IRoundEncrypting roundEncryptor)
        {
            this.keyExpander = keyExpander;
            this.roundEncryptor = roundEncryptor;
        }

        public void SetKey(byte[] key)
        {
            roundKeys = keyExpander.ExpandKey(key);
        }

        private void Crypt(ref byte[] res)
        {
            for (int i = 0; i < 16; i++)
            {
                res = roundEncryptor.RoundEncrypt(res, roundKeys[i]);
            }

            for (int i = 0; i < 4; i++)
            {
                (res[i], res[7 - i]) = (res[7 - i], res[i]);
            }
        }

        public byte[] Encrypt(byte[] data)
        {
            Crypt(ref data);
            return data;
        }

        public byte[] Decrypt(byte[] data)
        {
            for (int i = 0; i < 8; i++)
            {
                (roundKeys[i], roundKeys[15 - i]) = (roundKeys[15 - i], roundKeys[i]);
            }

            Crypt(ref data);
            return data;
        }
    }

    class DES : FeistelNetwork
    {
        byte[] startPermBlock = new byte[]
        {
            58, 50, 42, 34, 26, 18, 10, 02,
            60, 52, 44, 36, 28, 20, 12, 04,
            62, 54, 46, 38, 30, 22, 14, 06,
            64, 56, 48, 40, 32, 24, 16, 08,
            57, 49, 41, 33, 25, 17, 09, 01,
            59, 51, 43, 35, 27, 19, 11, 03,
            61, 53, 45, 37, 29, 21, 13, 05,
            63, 55, 47, 39, 31, 23, 15, 07
        };

        byte[] endPermBlock = new byte[]
        {
            40, 08, 48, 16, 56, 24, 64, 32,
            39, 07, 47, 15, 55, 23, 63, 31,
            38, 06, 46, 14, 54, 22, 62, 30,
            37, 05, 45, 13, 53, 21, 61, 29,
            36, 04, 44, 12, 52, 20, 60, 28,
            35, 03, 43, 11, 51, 19, 59, 27,
            34, 02, 42, 10, 50, 18, 58, 26,
            33, 01, 41, 09, 49, 17, 57, 25
        };

        public static void PBlock(ref byte[] bytes, byte[] permBlock)
        {
            byte[] res = new byte[permBlock.Length / 8];
            for (int i = 0; i < permBlock.Length; i++)
            {
                int newPos = permBlock[i] - 1;
                int bit = (bytes[newPos / 8] >> (7 - newPos % 8)) & 1;
                res[i / 8] |= (byte)(bit << (7 - i % 8));
            }

            bytes = res;
        }

        public static byte SBlock(byte[] bytes, byte[][] subBlock, int blockNum)
        {
            int i = (
                (bytes[(blockNum * 6 + 0) / 8] >> (6 - (blockNum * 6) % 8)) & 0b10
                |
                (bytes[(blockNum * 6 + 5) / 8] >> (7 - (blockNum * 6 + 5) % 8)) & 0b1
            );

            int j = (
                (bytes[(blockNum * 6 + 1) / 8] >> (4 - (blockNum * 6 + 1) % 8)) & 0b1000
                |
                (bytes[(blockNum * 6 + 2) / 8] >> (5 - (blockNum * 6 + 2) % 8)) & 0b110
                |
                (bytes[(blockNum * 6 + 4) / 8] >> (7 - (blockNum * 6 + 4) % 8)) & 0b1
            );
            return subBlock[i][j];
        }

        public DES(byte[] key) : base(new KeyExpander(), new RoundEncryptor())
        {
            SetKey(key);
        }

        public byte[] DESEncrypt(byte[] data)
        {
            byte[] res = new byte[data.Length];
            data.CopyTo(res, 0);
            PBlock(ref res, startPermBlock);
            res = Encrypt(res);
            PBlock(ref res, endPermBlock);
            return res;
        }

        public byte[] DESDecrypt(byte[] data)
        {
            byte[] res = new byte[data.Length];
            data.CopyTo(res, 0);
            PBlock(ref res, endPermBlock);
            res = Decrypt(res);
            PBlock(ref res, startPermBlock);
            return res;
        }
    }


    static class Program
    {
        public static string PrintBits(byte[] arr)
        {

            string res = "";
            for (int i = 0; i < arr.Length; i++)
            {
                var tmp = Convert.ToString(arr[i], 2);
                var pad = "";
                for (int j = 0; j < 8 - tmp.Length; j++)
                    pad += "0";
                
                res += pad + tmp + "|";
            }

            return res;
        }
        
        static void Main(string[] args)
        {
            byte[] data = Convert.FromHexString("123456ABCD132536");

            byte[] key = Convert.FromHexString("AABB09182736CCDD");
            Cipher cipher = new Cipher(key, Cipher.CryptRule.ECB);
            byte[] res = Array.Empty<byte>();
            cipher.Encrypt(data, ref res);
            byte[] decrypt = Array.Empty<byte>();
            cipher.Decrypt(res, ref decrypt);
            Console.ReadLine();
        }
    }
}