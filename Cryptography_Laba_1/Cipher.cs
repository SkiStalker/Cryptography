using System.Numerics;

namespace Cryptography_Laba_1;

public class Cipher
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
        byte[] cryptData = Array.Empty<byte>();
            
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