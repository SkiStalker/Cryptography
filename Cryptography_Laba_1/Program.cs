using System.Collections;
using System.Linq;
using System.Security.Cryptography;

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
        readonly byte[] suppressKeyTable = new byte[] { 14, 17,  11,  24,  01,  05,  03,  28,
                                                    15,  06,  21,  10,  23,  19,  12,  04,
                                                    26,  08,  16,  07,  27,  20,  13,  02,
                                                    41,  52,  31,  37,  47,  55,  30,  40,
                                                    51,  45,  33,  48,  44,  49,  39,  56,
                                                    34,  53,  46,  42,  50,  36,  29,  32};
        readonly byte[] removeEvenBitsTable = new byte[] { 57, 49, 41,  33,  25,  17,  09,  01,
                                                        58,  50,  42,  34,  26,  18,  10,  02,
                                                        59,  51,  43,  35,  27,  19 , 11 , 03,
                                                        60,  52,  44,  36,  63,  55,  47,  39,
                                                        31 , 23 , 15,  07 , 62,  54,  46,  37,
                                                        30,  22,  14 , 06 , 61,  53,  45,  37,
                                                        29,  21,  13,  05,  28 , 20,  12,  04};

        void CyclicRightShift(ref byte[] bytes, byte shiftCount, bool leftPart)
        {
            if (leftPart)
            {
                byte tmp = (byte)(bytes[3] >> 4);
                bytes[3] = (byte)((bytes[3] >> shiftCount)&0b11110000 | (bytes[2] << (8 - shiftCount)) | (bytes[3] & 0b00001111));
                bytes[2] = (byte)(bytes[2] >> (shiftCount) | (bytes[1] << (8 - shiftCount)));
                bytes[1] = (byte)(bytes[1] >> (shiftCount) | (bytes[0] << (8 - shiftCount)));
                bytes[0] = (byte)(bytes[0] >> (shiftCount) | (tmp << (8 - shiftCount)));
            }
            else
            {
                byte tmp = bytes[6];
                bytes[6] = (byte)((bytes[6] >> shiftCount) | (bytes[5] << (8 - shiftCount)));
                bytes[5] = (byte)((bytes[5] >> shiftCount) | (bytes[4] << (8 - shiftCount)));
                bytes[4] = (byte)((bytes[4] >> shiftCount) | (bytes[3] << (8 - shiftCount)));
                bytes[3] = (byte)((bytes[3] >> shiftCount) | (tmp << (8 - shiftCount) >> 4) | bytes[3] & 0b11110000);
            }
        }

        void CyclicLeftShift(ref byte[] bytes, int shiftCount, bool leftPart)
        {
            if (leftPart)
            {
                byte tmp = bytes[0];
                bytes[0] = (byte)((bytes[0] << shiftCount) | (bytes[1] >> (8 - shiftCount)));
                bytes[1] = (byte)((bytes[1] << shiftCount) | (bytes[2] >> (8 - shiftCount)));
                bytes[2] = (byte)((bytes[2] << shiftCount) | (bytes[3] >> (8 - shiftCount)));
                bytes[3] = (byte)((bytes[3] << shiftCount) | (tmp >> (8 - shiftCount) << 4)   | bytes[3] & 0b00001111);
            }
            else
            {
                byte tmp = (byte)(bytes[3] & 0b00001111);
                bytes[3] = (byte)((tmp << shiftCount) & 0b00001111 | (bytes[4] >> (8 - shiftCount)) | bytes[3] & 0b11110000);
                bytes[4] = (byte)((bytes[4] << shiftCount) | (bytes[5] >> (8 - shiftCount)));
                bytes[5] = (byte)((bytes[5] << shiftCount) | (bytes[6] >> (8 - shiftCount)));
                bytes[6] = (byte)((bytes[6] << shiftCount) | (tmp >> (4 - shiftCount)));
            }
        }

        public byte[][] ExpandKey(byte[] key)
        {
            byte[][] result = new byte[16][];
            FeistelСipher.PBlock(ref key, removeEvenBitsTable);
            for (int i = 0; i < 16; i++)
            {
                byte[] roundKey = new byte[7];
                key.CopyTo(roundKey, 0);
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    if (i % 2 == 0)
                    {

                        CyclicRightShift(ref roundKey, 1, true);
                        CyclicLeftShift(ref roundKey, 1, false);
                        FeistelСipher.PBlock(ref roundKey, suppressKeyTable);
                        result[i] = roundKey;
                    }
                    else
                    {
                        CyclicLeftShift(ref roundKey, 1, true);
                        CyclicRightShift(ref roundKey, 1, false);
                        FeistelСipher.PBlock(ref roundKey, suppressKeyTable);
                        result[i] = roundKey;
                    }
                }
                else
                {
                    if (i % 2 == 0)
                    {
                        CyclicRightShift(ref roundKey, 2, true);
                        CyclicLeftShift(ref roundKey, 2, false);
                        FeistelСipher.PBlock(ref roundKey, suppressKeyTable);
                        result[i] = roundKey;
                    }
                    else
                    {
                        CyclicLeftShift(ref roundKey, 2, true);
                        CyclicRightShift(ref roundKey, 2, false);
                        FeistelСipher.PBlock(ref roundKey, suppressKeyTable);
                        result[i] = roundKey;
                    }
                }

            }
            return result;
        }
    }

    class RoundEncryptor : IRoundEncrypting
    {
        byte[][][] subTables = new byte[][][]
        {
            new byte[][] {
                new byte[] {14, 04,  13,  01,  02,  15,  11,  08,  03,  10,  06,  12,  05,  09,  00,  07},
                new byte[] { 00,  15,  07,  04,  14,  02,  13,  10,  03,  06,  12,  11,  09,  05,  03, 08},
                new byte[] { 04,  01,  14,  07,  13, 06,  02,  11,  15,  12,  09,  07,  03,  10, 05,  00},
                new byte[] { 15,  12,  08,  02,  04,  09,  01,  07,  05,  11,  03,  14,  10,  00,  06,  13}

            },
            new byte[][]
            {
                new byte[] { 15, 01, 08, 14, 06, 11, 03, 04, 09, 07, 02, 13, 12, 00, 05, 10 },
                new byte[] { 03, 13, 04, 07, 15, 02, 08, 14, 12, 00, 01, 10, 06, 09, 11, 05 },
                new byte[] { 00, 14, 07, 11, 10, 04, 13, 01, 05, 08, 12, 06, 09, 03, 02, 15 },
                new byte[] { 13, 08, 10, 01, 03, 15, 04, 02, 11, 06, 07, 12, 00, 05, 14, 09 }
            },

            new byte [][] {
                new byte[] {10, 00, 09, 14, 06, 03, 15, 05, 01, 13, 12, 07, 11, 04, 02, 08},
                new byte[] {13, 07, 00, 09, 03, 04, 06, 10, 02, 08, 05, 14, 12, 11, 15, 01},
                new byte[] {13, 06, 04, 09, 08, 15, 03, 00, 11, 01, 02, 12, 05, 10, 14, 07},
                new byte[] {01, 10, 13, 00, 06, 09, 08, 07, 04, 15, 14, 03, 11, 05, 02, 12}
            },
            new byte [][] {
                new byte[] {07, 13, 14, 03, 00, 06, 09, 10, 01, 02, 08, 05, 01, 12, 04, 15},
                new byte[] {13, 08, 11, 05, 06, 15, 00, 03, 04, 07, 02, 12, 01, 10, 14, 09},
                new byte[] {10, 06, 09, 00, 12, 11, 07, 13, 15, 01, 03, 14, 05, 02, 08, 04},
                new byte[] {03, 15, 00, 06, 10, 01, 13, 08, 09, 04, 05, 11, 12, 07, 02, 14}
            },

            new byte [][] {
                new byte[] {02, 12, 04, 01, 07, 10, 11, 06, 08, 05, 03, 15, 13, 00, 14, 09},
                new byte[] {14, 11, 02, 12, 04, 07, 13, 01, 05, 00, 15, 10, 03, 09, 08, 06},
                new byte[] {04, 02, 01, 11, 10, 13, 07, 08, 15, 09, 12, 05, 06, 03, 00, 14},
                new byte[] {11, 08, 12, 07, 01, 14, 02, 13, 06, 15, 00, 09, 10, 04, 05, 03}
            },

            new byte [][] {
                new byte[] {12, 01, 10, 15, 09, 02, 06, 08, 00, 13, 03, 04, 14, 07, 05, 11},
                new byte[] {10, 15, 04, 02, 07, 12, 09, 05, 06, 01, 13, 14, 00, 11, 03, 08},
                new byte[] {09, 14, 15, 05, 02, 08, 12, 03, 07, 00, 04, 10, 01, 13, 11, 06},
                new byte[] {04, 03, 02, 12, 09, 05, 15, 10, 11, 14, 01, 07, 10, 00, 08, 13}
            },

            new byte [][] {
                new byte[] {04, 11, 02, 14, 15, 00, 08, 13, 03, 12, 09, 07, 05, 10, 06, 01},
                new byte[] {13, 00, 11, 07, 04, 09, 01, 10, 14, 03, 05, 12, 02, 15, 08, 06},
                new byte[] {01, 04, 11, 13, 12, 03, 07, 14, 10, 15, 06, 08, 00, 05, 09, 02},
                new byte[] {06, 11, 13, 08, 01, 04, 10, 07, 09, 05, 00, 15, 14, 02, 03, 12}
            },

            new byte [][] {
                new byte[] {13, 02, 08, 04, 06, 15, 11, 01, 10, 09, 03, 14, 05, 00, 12, 07},
                new byte[] {01, 15, 13, 08, 10, 03, 07, 04, 12, 05, 06, 11, 10, 14, 09, 02},
                new byte[] {07, 11, 04, 01, 09, 12, 14, 02, 00, 06, 10, 10, 15, 03, 05, 08},
                new byte[] {02, 01, 14, 07, 04, 10, 05, 13, 15, 19, 09, 09, 03, 05, 06, 11}
            }
        };


        byte[] expandBlock = new byte[]
        {
            32,  01,  02,  03,  04,  05,
            04,  05,  06,  07,  08,  09,
            08,  09,  10,  11,  12,  13,
            12,  13,  14,  15,  16,  17,
            16,  17,  18,  19,  20,  21,
            20,  21,  22,  23,  24,  25,
            24,  25,  26,  27,  28,  29,
            28,  29,  31,  31,  32,  01
        };

        byte[] straightPerBlock = new byte[]
        {
            16,  07,  20,  21,  29,  12,  28,  17,
            01,  15,  23,  26,  05,  18,  31,  10,
            02,  08,  24,  14,  32,  27,  03,  09,
            19,  13,  30,  06,  22,  11,  04,  25
        };

        public byte[] RoundEncrypt(byte[] data, byte[] roundKey)
        {
            byte[] res = new byte[data.Length];
            data.CopyTo(res, 0);
            byte[] rightPart = new byte[4];
            res.CopyTo(rightPart, 4);
            byte[] newRightPart = new byte[4];

            DES.PBlock(ref rightPart, expandBlock);

            for (int i = 0; i < 6; i++)
            {
                rightPart[i] ^= roundKey[i];
            }

            for (int i = 0; i < 8; i++)
            {
                byte tmp = DES.SBlock(rightPart, subTables[i], i);
                newRightPart[i / 2] = (byte)(tmp >> (4 * (1 % 2)));
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
        byte[] initVector;
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



        Cipher(byte[] key, CryptRule cryptRule, byte[] initVector, params byte[] args)
        {
            des = new DES(key);
            this.cryptRule = cryptRule;
            this.initVector = initVector;
            this.args = args;

        }

        void Encrypt(byte[] data, ref byte[] encryptData)
        {
            byte data_mod_len = (byte)(data.Length % 8);
            if (data_mod_len == 0)
            {
                data_mod_len = 8;
            }

            byte[] padding = new byte[data_mod_len];
            for (int i = 0; i < data_mod_len; i++)
            {
                padding[i] = data_mod_len;
            }

            data.Concat(padding);

            switch (cryptRule)
            {
                case CryptRule.ECB:
                    {
                        for(int i = 0; i < data.Length; i+= 8)
                        {
                            byte[] cryptData = des.DESEncrypt(new ArraySegment<byte>(data, i, 8).Array ?? throw new NullReferenceException());
                            for(int j = 0; j < cryptData.Length; j++)
                            {
                                encryptData[j + i] = cryptData[j];
                            }
                        }
                        break;
                    }
                default: throw new NotImplementedException();
            }
        }

        void Decrypt(byte[] data, ref byte[] decryptData)
        {

        }

        void Encrypt(string inputFile, string outputFile)
        {
            byte[] data = File.ReadAllBytes(inputFile);
            byte[] res = new byte[0];
            Encrypt(data, ref res);
            File.WriteAllBytes(outputFile, res);
        }

        void Decrypt(string inputFile, string outputFile)
        {
            byte[] data = File.ReadAllBytes(inputFile);
            byte[] res = new byte[0];
            Decrypt(data, ref res);
            File.WriteAllBytes(outputFile, res);
        }
    }

    class FeistelСipher : IEncrypting
    {

        byte[][] roundKeys = new byte[0][];

        private IKeyExpanding keyExpander;
        private IRoundEncrypting roundEncryptor;

        public FeistelСipher(IKeyExpanding keyExpander, IRoundEncrypting roundEncryptor)
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

    class DES : FeistelСipher
    {
        byte[] startPermBlock = new byte[]
            {58, 50, 42, 34, 26, 18, 10, 02,
            60, 52, 44, 36, 28, 20, 12, 04,
            62, 54, 46, 38, 30, 22, 14, 06,
            64, 56, 48, 40, 32, 24, 16, 08,
            57, 49, 41, 33, 25, 17, 09, 01,
            59, 51, 43, 35, 27, 19, 11, 03,
            61, 53, 45, 37, 29, 21, 13, 05,
            63, 55, 47, 39, 31, 23, 15, 07};

        byte[] endPermBlock = new byte[]
            {40, 08, 48, 16, 56, 24, 64, 32,
            39, 07, 47, 15, 55, 23, 63, 31,
            38, 06, 46, 14, 54, 22, 62, 30,
            37, 05, 45, 13, 53, 21, 61, 29,
            36, 04, 44, 12, 52, 20, 60, 28,
            35, 03, 43, 11, 51, 19, 59, 27,
            34, 02, 42, 10, 50, 18, 58, 26,
            33, 01, 41, 09, 49, 17, 57, 25};

        static public void PBlock(ref byte[] bytes, byte[] permBlock)
        {
            byte[] res = new byte[permBlock.Length / 8];
            for (int i = 0; i < permBlock.Length; i++)
            {
                int newPos = permBlock[i] - 1;
                int bit = (bytes[i / 8] >> (i % 8)) & 1;
                res[i / 8] |= (byte)(bit << (newPos %8));
            }
            bytes = res;
        }

        static public byte SBlock(byte[] bytes, byte[][] subBlock, int blockNum)
        {

            int i = (
                (bytes[(blockNum * 6 + 0)/ 8] >> (6  - (blockNum * 6) % 8)) & 0b10
                |
                (bytes[(blockNum * 6 + 5) / 8] >> (7 - (blockNum * 6 + 5) % 8)) & 0b1
                );

            int j = (
                (bytes[(blockNum * 6 + 1) / 8] >> (4  - (blockNum * 6 + 1) % 8)) & 0b1000
                |
                (bytes[(blockNum * 6 + 2) / 8] >> (5  - (blockNum * 6 + 2) % 8)) & 0b110
                |
                (bytes[(blockNum * 6 + 4) / 8] >> (7  - (blockNum * 6 + 4) % 8)) & 0b1
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
            Encrypt(res);
            PBlock(ref res, endPermBlock);
            return res;
        }

        public byte[] DESDecrypt(byte[] data)
        {
            byte[] res = new byte[data.Length];
            data.CopyTo(res, 0);
            PBlock(ref res, endPermBlock);
            Encrypt(res);
            PBlock(ref res, startPermBlock);
            return res;
        }
    }


    class Progam
    {
        static void Main(string[] args)
        {
            Console.ReadLine();
        }
    }
}