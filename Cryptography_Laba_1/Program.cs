using System.Numerics;


namespace Cryptography_Laba_1
{
    internal interface IKeyExpanding
    {
        byte[][] ExpandKey(byte[] key);
    }

    internal interface IRoundEncrypting
    {
        byte[] RoundEncrypt(byte[] data, byte[] roundKey);
    }

    internal interface IEncrypting
    {
        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);
        void SetKey(byte[] key);
    }

    internal class KeyExpander : IKeyExpanding
    {
        private readonly byte[] suppressKeyTable = new byte[]
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
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
        };

        private byte[] LeftShift(byte[] key, int n)
        {
            byte[] result = new byte[key.Length];
            for (int i = 0; i < key.Length; i++)
            {
                result[i] = (byte)((key[i] << n) | (key[(i + 1) % key.Length] >> (8 - n)));
            }

            return result;
        }

        private void GetKeyParts(byte[] key, byte[] leftPart, byte[] rightPart)
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

        private void MergeKeys(byte[] key, byte[] leftPart, byte[] rightPart)
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
                int off = i is 0 or 1 or 8 or 15 ? 1 : 2;

                byte[] leftPart = new byte[4];
                byte[] rightPart = new byte[4];
                GetKeyParts(key, leftPart, rightPart);


                leftPart = LeftShift(leftPart, off);
                leftPart[3] = (byte)(((leftPart[3] & (off | 1)) << 4) | leftPart[3] & 0b11110000);


                rightPart = LeftShift(rightPart, off);
                rightPart[3] = (byte)(((rightPart[3] & (off | 1)) << 4) | rightPart[3] & 0b11110000);

                MergeKeys(key, leftPart, rightPart);

                
                byte[] roundKey = new byte[key.Length];
                key.CopyTo(roundKey, 0);
                DES.PBlock(ref roundKey, suppressKeyTable);
                result[i] = roundKey;
            }

            return result;
        }
    }

    internal class RoundEncryptor : IRoundEncrypting
    {
        private static readonly byte[][][] subTables = {
            new[]
            {
                new byte[] { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                new byte[] { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                new byte[] { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                new byte[] { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
            },

            new[]
            {
                new byte[] { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                new byte[] { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                new byte[] { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                new byte[] { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
            },

            new[]
            {
                new byte[] { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                new byte[] { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                new byte[] { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                new byte[] { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            },

            new[]
            {
                new byte[] { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                new byte[] { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                new byte[] { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                new byte[] { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            },

            new[]
            {
                new byte[] { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                new byte[] { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                new byte[] { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                new byte[] { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            },

            new[]
            {
                new byte[] { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                new byte[] { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                new byte[] { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                new byte[] { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            },

            new[]
            {
                new byte[] { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                new byte[] { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                new byte[] { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                new byte[] { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            },

            new[]
            {
                new byte[] { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                new byte[] { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                new byte[] { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                new byte[] { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            }
        };

        // TODO: make static
        private readonly byte[] expandBlock = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        private readonly byte[] straightPerBlock = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
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
                (res[i], res[i + 4]) = (res[i + 4], res[i]);
            }

            return res;
        }
    }

    internal class Cipher
    {
        private readonly IEncrypting blockCryptAlg;
        private readonly CryptRule cryptRule;
        private readonly byte[]? initVector;

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

        public static byte[] GenerateInitVector()
        {
            byte[] initVector = new byte[8];
            new Random().NextBytes(initVector);
            return initVector;
        }


        public Cipher(byte[] key, CryptRule cryptRule, byte[]? initVector = null)
        {
            if (key.Length != 8)
            {
                throw new Exception("Key length not equal 64 bits");
            }

            if (initVector != null && initVector.Length != 8)
            {
                throw new Exception("Init vector length not equal 64 bits");
            }

            blockCryptAlg = new DES(key);
            this.cryptRule = cryptRule;
            this.initVector = initVector;
        }

        public void Encrypt(byte[] data, ref byte[] encryptData)
        {
            int inputDataLength = data.Length;
            byte dataModLen = (byte)(8 - data.Length % 8);
            int off = 0;
            BigInteger? delta = null;
            byte[] padding = new byte[dataModLen];
            byte[]? tmpInitVector = (byte[]?)initVector?.Clone();
            byte[] cryptData;
            
            for (int i = 0; i < dataModLen; i++)
            {
                padding[i] = dataModLen;
            }

            data = data.Concat(padding).ToArray();

            if (cryptRule == CryptRule.RD || cryptRule == CryptRule.RDH)
            {
                if (tmpInitVector == null)
                {
                    throw new Exception("Null reference to init vector");
                }

                off = 8;
                encryptData = new byte[data.Length + 8];

                cryptData = blockCryptAlg.Encrypt(tmpInitVector);
                delta = new BigInteger(tmpInitVector
                    .Take(new Range(tmpInitVector.Length / 2, tmpInitVector.Length))
                    .ToArray());

                for (int i = 0; i < cryptData.Length; i++)
                {
                    encryptData[i] = cryptData[i];
                }
                
                if (cryptRule == CryptRule.RDH)
                {
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }

                    off = 8 * 2;
                    encryptData = new byte[data.Length + 8 * 2];
                    for (int i = 0; i < cryptData.Length; i++)
                    {
                        encryptData[i] = cryptData[i];
                    }
                    byte[] hash = new byte[8];
                    for (int i = 0; i < inputDataLength; i++)
                    {
                        hash[i % 8] ^= data[i];
                    }

                    for (int i = 0; i < hash.Length; i++)
                    {
                        hash[i] ^= tmpInitVector[i];
                    }

                    cryptData = blockCryptAlg.Encrypt(hash);

                    for (int i = 0; i < cryptData.Length; i++)
                    {
                        encryptData[i + 8] = cryptData[i];
                    }
                    
                    byte[] tmp = (new BigInteger(tmpInitVector) + delta).Value.ToByteArray() ??
                                 throw new NullReferenceException();
                    tmpInitVector = tmp.Skip(8 - tmp.Length).ToArray();
                }
            }
            else
            {
                encryptData = new byte[data.Length];
            }


            for (int i = 0; i < data.Length; i += 8)
            {
                byte[] tmpData = data.Take(new Range(i, i + 8)).ToArray() ??
                                 throw new NullReferenceException();

                switch (cryptRule)
                {
                    case CryptRule.ECB:
                    {
                        cryptData = blockCryptAlg.Encrypt(tmpData);

                        break;
                    }
                    case CryptRule.CBC:
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }


                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            tmpData[k] ^= tmpInitVector[k];
                        }

                        cryptData = blockCryptAlg.Encrypt(tmpData);

                        tmpInitVector = cryptData;
                        break;
                    }
                    case CryptRule.CFB:
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            cryptData[k] ^= tmpData[k];
                        }

                        tmpInitVector = cryptData;

                        break;
                    }
                    case CryptRule.OFB:
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                        cryptData.CopyTo(tmpInitVector, 0);

                        for (int k = 0; k < cryptData.Length; k++)
                        {
                            cryptData[k] ^= tmpData[k];
                        }

                        break;
                    }
                    case CryptRule.CTR:
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            cryptData[k] ^= tmpData[k];
                        }

                        byte[] tmp = (new BigInteger(tmpInitVector) + 1).ToByteArray();
                        tmpInitVector = tmp.Skip(8 - tmp.Length).ToArray();

                        break;
                    }
                    case CryptRule.RD: case CryptRule.RDH:
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        if (delta == null)
                        {
                            throw new Exception("Null reference to delta");
                        }

                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            tmpData[k] ^= tmpInitVector[k];
                        }

                        cryptData = blockCryptAlg.Encrypt(tmpData);

                        byte[] tmp = (new BigInteger(tmpInitVector) + delta).Value.ToByteArray() ??
                                     throw new NullReferenceException();
                        tmpInitVector = tmp.Skip(8 - tmp.Length).ToArray();

                        break;
                    }
                    default: throw new NotImplementedException();
                }

                for (int j = 0; j < cryptData.Length; j++)
                {
                    encryptData[j + i + off] = cryptData[j];
                }
            }
        }

        public void Decrypt(byte[] data, out byte[] decryptData)
        {
            byte[] cryptData = Array.Empty<byte>();
            byte[]? tmpInitVector = (byte[]?)initVector?.Clone();
            BigInteger? delta = null;
            int off = 0;
            byte[] hash = Array.Empty<byte>();
            if (cryptRule == CryptRule.RD)
            {
                off = -8;
                decryptData = new byte[data.Length - 8];
            }
            else if (cryptRule == CryptRule.RDH)
            {
                off = -(2 * 8);
                decryptData = new byte[data.Length - 8 * 2];
            }
            else
            {
                decryptData = new byte[data.Length];
            }


            for (int i = 0; i < data.Length; i += 8)
            {
                byte[] tmpData = data.Take(new Range(i, i + 8)).ToArray() ??
                                 throw new NullReferenceException();


                switch (cryptRule)
                {
                    case CryptRule.ECB:
                    {
                        cryptData = blockCryptAlg.Decrypt(tmpData);
                        break;
                    }
                    case CryptRule.CBC:
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        cryptData = blockCryptAlg.Decrypt(tmpData);

                        for (int k = 0; k < cryptData.Length; k++)
                        {
                            cryptData[k] ^= tmpInitVector[k];
                        }

                        tmpInitVector = tmpData;
                        break;
                    }
                    case CryptRule.CFB:
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            cryptData[k] ^= tmpData[k];
                        }

                        tmpInitVector = tmpData;
                        break;
                    }
                    case CryptRule.OFB:
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                        cryptData.CopyTo(tmpInitVector, 0);

                        for (int k = 0; k < cryptData.Length; k++)
                        {
                            cryptData[k] ^= tmpData[k];
                        }

                        break;
                    }
                    case CryptRule.CTR:
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            cryptData[k] ^= tmpData[k];
                        }

                        byte[] tmp = (new BigInteger(tmpInitVector) + 1).ToByteArray();
                        tmpInitVector = tmp.Skip(8 - tmp.Length).ToArray();
                        break;
                    }
                    case CryptRule.RD:
                    {
                        if (i == 0)
                        {
                            tmpInitVector = blockCryptAlg.Decrypt(tmpData);
                            delta = new BigInteger(tmpInitVector
                                .Take(new Range(tmpInitVector.Length / 2, tmpInitVector.Length))
                                .ToArray());
                        }
                        else
                        {
                            if (tmpInitVector == null)
                            {
                                throw new Exception("Null reference to init vector");
                            }

                            if (delta == null)
                            {
                                throw new Exception("Null reference to delta");
                            }

                            cryptData = blockCryptAlg.Decrypt(tmpData);

                            for (int k = 0; k < tmpData.Length; k++)
                            {
                                cryptData[k] ^= tmpInitVector[k];
                            }

                            byte[] tmp = (new BigInteger(tmpInitVector) + delta).Value.ToByteArray() ??
                                         throw new NullReferenceException();
                            tmpInitVector = tmp.Skip(8 - tmp.Length).ToArray();
                        }

                        break;
                    }
                    case CryptRule.RDH:
                    {
                        if (i == 0)
                        {
                            tmpInitVector = blockCryptAlg.Decrypt(tmpData);
                            delta = new BigInteger(tmpInitVector
                                .Take(new Range(tmpInitVector.Length / 2, tmpInitVector.Length))
                                .ToArray());
                        }
                        else if (i == 8)
                        {
                            if (tmpInitVector == null)
                            {
                                throw new Exception("Null reference to init vector");
                            }
                            
                            hash = blockCryptAlg.Decrypt(tmpData);
                            for (int k = 0; k < tmpData.Length; k++)
                            {
                                hash[k] ^= tmpInitVector[k];
                            }
                            byte[] tmp = (new BigInteger(tmpInitVector) + delta)?.ToByteArray() ??
                                         throw new NullReferenceException();
                            tmpInitVector = tmp.Skip(8 - tmp.Length).ToArray();
                        }
                        else
                        {
                            if (tmpInitVector == null)
                            {
                                throw new Exception("Null reference to init vector");
                            }

                            if (delta == null)
                            {
                                throw new Exception("Null reference to delta");
                            }

                            cryptData = blockCryptAlg.Decrypt(tmpData);

                            for (int k = 0; k < tmpData.Length; k++)
                            {
                                cryptData[k] ^= tmpInitVector[k];
                            }

                            byte[] tmp = (new BigInteger(tmpInitVector) + delta).Value.ToByteArray() ??
                                         throw new NullReferenceException();
                            tmpInitVector = tmp.Skip(8 - tmp.Length).ToArray();
                        }

                        break;
                    }
                    
                    default: throw new NotImplementedException();
                }

                for (int j = 0; j < cryptData.Length; j++)
                {
                    decryptData[j + i + off] = cryptData[j];
                }
            }


            int paddingLen = decryptData.Last();
            decryptData = decryptData.Take(decryptData.Length - paddingLen).ToArray();
            
            if (cryptRule == CryptRule.RDH)
            {
                byte[] tmpHash = new byte[8];
                for (int i = 0; i < decryptData.Length; i++)
                {
                    tmpHash[i % 8] ^= decryptData[i];
                }

                for (int i = 0; i < tmpHash.Length; i++)
                {
                    if (tmpHash[i] != hash[i])
                    {
                        throw new InvalidDataException();
                    }
                }
            }
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
            Decrypt(data, out byte[] res);
            File.WriteAllBytes(outputFile, res);
        }
    }

    internal class FeistelNetwork : IEncrypting
    {
        private byte[][] roundKeys = Array.Empty<byte[]>();

        private readonly IKeyExpanding keyExpander;
        private readonly IRoundEncrypting roundEncryptor;

        public FeistelNetwork(IKeyExpanding keyExpander, IRoundEncrypting roundEncryptor)
        {
            this.keyExpander = keyExpander;
            this.roundEncryptor = roundEncryptor;
        }

        public void SetKey(byte[] key)
        {
            roundKeys = keyExpander.ExpandKey(key);
        }

        private byte[] Crypt(byte[] data, bool encrypt)
        {
            byte[] res = new byte[data.Length];
            data.CopyTo(res, 0);

            int begin = encrypt ? 0 : 15;
            int end = encrypt ? 16 : -1;
            int step = encrypt ? 1 : -1;

            for (int i = begin; i != end; i += step)
            {
                res = roundEncryptor.RoundEncrypt(res, roundKeys[i]);
            }

            for (int i = 0; i < 4; i++)
            {
                (res[i], res[i + 4]) = (res[i + 4], res[i]);
            }

            return res;
        }

        public byte[] Encrypt(byte[] data)
        {
            return Crypt(data, true);
        }

        public byte[] Decrypt(byte[] data)
        {
            return Crypt(data, false);
        }
    }

    internal class DES : FeistelNetwork
    {
        private readonly byte[] startPermBlock = new byte[]
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

        private readonly byte[] endPermBlock = new byte[]
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };

        public static void PBlock(ref byte[] bytes, byte[] permBlock)
        {
            byte[] res = new byte[permBlock.Length / 8];
            for (int i = 0; i < permBlock.Length; i++)
            {
                int pos = permBlock[i] - 1;
                int bit = (bytes[pos / 8] >> (7 - pos % 8)) & 1;
                res[i / 8] |= (byte)(bit << (7 - i % 8));
            }

            bytes = res;
        }

        public static byte SBlock(byte[] bytes, byte[][] subBlock, int blockNum)
        {
            int i = (
                (bytes[(blockNum * 6 + 0) / 8] >> (7 - (blockNum * 6) % 8)) << 1 & 0b10
                |
                (bytes[(blockNum * 6 + 5) / 8] >> (7 - (blockNum * 6 + 5) % 8)) & 0b1
            );

            int j = (
                (bytes[(blockNum * 6 + 1) / 8] >> (7 - (blockNum * 6 + 1) % 8)) << 3 & 0b1000
                |
                (bytes[(blockNum * 6 + 2) / 8] >> (7 - (blockNum * 6 + 2) % 8)) << 2 & 0b100
                |
                (bytes[(blockNum * 6 + 3) / 8] >> (7 - (blockNum * 6 + 3) % 8)) << 1 & 0b10
                |
                (bytes[(blockNum * 6 + 4) / 8] >> (7 - (blockNum * 6 + 4) % 8)) & 0b1
            );
            return subBlock[i][j];
        }

        public DES(byte[] key) : base(new KeyExpander(), new RoundEncryptor())
        {
            SetKey(key);
        }

        private byte[] Crypt(byte[] data, bool encrypt)
        {
            byte[] res = new byte[data.Length];
            data.CopyTo(res, 0);
            PBlock(ref res, startPermBlock);
            res = encrypt ? base.Encrypt(res) : base.Decrypt(res);
            PBlock(ref res, endPermBlock);
            return res;
        }

        public new byte[] Encrypt(byte[] data)
        {
            return Crypt(data, true);
        }

        public new byte[] Decrypt(byte[] data)
        {
            return Crypt(data, false);
        }
    }


    internal static class Program
    {
        public static string PrintBits(byte[] arr)
        {
            string res = "";
            foreach (byte t in arr)
            {
                string tmp = Convert.ToString(t, 2);
                string pad = "";
                for (int j = 0; j < 8 - tmp.Length; j++)
                    pad += "0";

                res += pad + tmp;
            }

            return res;
        }

        private static void Main()
        {

            byte[] key = Cipher.GenerateKey();

            byte[] initVector = Cipher.GenerateInitVector();

            Cipher cipher = new Cipher(key, Cipher.CryptRule.RDH, initVector);
            Console.WriteLine($"Key: {Convert.ToHexString(key)}");
            Console.WriteLine($"Init vector: {Convert.ToHexString(initVector)}");
            cipher.Encrypt("C:\\Users\\79832\\Documents\\1.txt", "C:\\Users\\79832\\Documents\\1.crypt");
            
            cipher.Decrypt("C:\\Users\\79832\\Documents\\1.crypt", "C:\\Users\\79832\\Documents\\1.decrypt.txt");
            Console.WriteLine("Finished");
            Console.ReadLine();
        }
    }
}