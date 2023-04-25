using Block_Cryptography_Algorithm;

namespace Rijndael;

internal sealed class RijndaelRoundEncryptor : IRoundEncrypting
{
    private int localRoundsCount;
    public byte[]? SBox { get; set; }

    public byte[]? MixColumnsPolynomial { get; set; }

    public byte Module { get; set; }

    private int roundsCount;
    public int RoundsCount
    {
        set
        {
            localRoundsCount = value;
            roundsCount = value;
        }
        get => roundsCount;
    }

    public bool Encrypt { get; set; }

    private byte[] GetShiftValues(int blockLength)
    {
        int nb = blockLength / 4;
        if (nb == 4 || nb == 6)
        {
            return new byte[] { 1, 2, 3 };
        }
        else if (nb == 8)
        {
            return new byte[] { 1, 3, 4 };
        }
        else
        {
            throw new ArgumentException("Incorrect block length");
        }
    }


    private byte RecGMul(byte a, byte b)
    {
        if (a == 3 || a == 2 || a == 1)
        {
            return GMul(a, b);
        }
        else if (a == 9)
        {
            return (byte)(GMul(2, GMul(2, GMul(2, b))) ^ b);
        }
        else if (a == 11)
        {
            return (byte)(GMul(2, (byte)(GMul(2, GMul(2, b)) ^ b)) ^ b);
        }
        else if (a == 13)
        {
            return (byte)(GMul(2, GMul(2, (byte)(GMul(2, b) ^ b))) ^ b);
        }
        else if (a == 14)
        {
            return GMul(2, (byte)(GMul(2, (byte)(GMul(2, b) ^ b )) ^ b));
        }
        else
        {
            return 1;
        }
    }

    private byte GMul(byte a, byte b)
    {
        byte p = 0;

        for (int counter = 0; counter < 8; counter++)
        {
            if ((b & 1) != 0)
            {
                p ^= a;
            }

            bool hiBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (hiBitSet)
            {
                a ^= Module;
            }

            b >>= 1;
        }

        return p;
    }

    private byte[] MixColumns(byte[] state)
    {
        if (MixColumnsPolynomial == null)
        {
            throw new NullReferenceException();
        }

        byte[] res = new byte[state.Length];

        for (int i = 0; i < state.Length; i += 4)
        {
            res[i] = (byte)(RecGMul(MixColumnsPolynomial[3], state[i]) ^
                            RecGMul(MixColumnsPolynomial[0], state[i + 1]) ^
                            RecGMul(MixColumnsPolynomial[1], state[i + 2]) ^
                            RecGMul(MixColumnsPolynomial[2], state[i + 3]));

            res[i + 1] = (byte)(RecGMul(MixColumnsPolynomial[2], state[i]) ^
                                RecGMul(MixColumnsPolynomial[3], state[i + 1]) ^
                                RecGMul(MixColumnsPolynomial[0], state[i + 2]) ^
                                RecGMul(MixColumnsPolynomial[1], state[i + 3]));

            res[i + 2] = (byte)(RecGMul(MixColumnsPolynomial[1], state[i]) ^
                                RecGMul(MixColumnsPolynomial[2], state[i + 1]) ^
                                RecGMul(MixColumnsPolynomial[3], state[i + 2]) ^
                                RecGMul(MixColumnsPolynomial[0], state[i + 3]));

            res[i + 3] = (byte)(RecGMul(MixColumnsPolynomial[0], state[i]) ^
                                RecGMul(MixColumnsPolynomial[1], state[i + 1]) ^
                                RecGMul(MixColumnsPolynomial[2], state[i + 2]) ^
                                RecGMul(MixColumnsPolynomial[3], state[i + 3]));
        }

        return res;
    }

    private void ShiftRows(byte[] state, byte[] c)
    {
        for (int i = 1; i < 4; i++)
        {
            for (int k = 0; k < c[i - 1]; k++)
            {
                byte t = state[i];
                for (int j = 0; j < state.Length / 4 - 1; j++)
                {
                    state[j * 4 + i] = state[(j + 1) * 4 + i];
                }
                state[(state.Length / 4 - 1) * 4 + i] = t;
            }
        }
    }

    private void InverseShiftRows(byte[] state, byte[] c)
    {
        for (int i = 1; i < 4; i++)
        {
            for (int k = 0; k < c[i - 1]; k++)
            {
                byte t = state[(state.Length / 4 - 1) * 4 + i];
                for (int j = state.Length / 4 - 1; j > 0; j--)
                {
                    state[j * 4 + i] = state[(j - 1) * 4 + i];
                }
                state[i] = t;
                
            }
        }
    }

    public byte[] RoundEncrypt(byte[] data, byte[] roundKey)
    {
        if (SBox == null || MixColumnsPolynomial == null)
        {
            throw new NullReferenceException();
        }

        byte[] res = new byte[data.Length];
        byte[] c = GetShiftValues(data.Length);
        if (Encrypt)
        {
            for (int i = 0; i < data.Length; i++)
            {
                res[i] = SBox[data[i]];
            }
            ShiftRows(res, c);
            if (localRoundsCount != 1)
            {
                res = MixColumns(res);
                localRoundsCount -= 1;
            }
            for (int i = 0; i < res.Length; i++)
            {
                res[i] ^= roundKey[i];
            }
        }
        else
        {
            for (int i = 0; i < res.Length; i++)
            {
                res[i] = (byte)(data[i] ^ roundKey[i]);
            }


            if (localRoundsCount != RoundsCount)
            {
                res = MixColumns(res);
            }
            localRoundsCount -= 1;

            InverseShiftRows(res, c);

            for (int i = 0; i < data.Length; i++)
            {
                res[i] = SBox[res[i]];
            }
        }

        return res;
    }
}