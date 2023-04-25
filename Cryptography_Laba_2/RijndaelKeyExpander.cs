using Cryptography_Laba_1;

namespace Cryptography_Laba_2;

public class RijndaelKeyExpanded : IKeyExpanding
{
    public byte Mod { get; set; }
    public int BlockLength { get; set; }
    public byte RoundsCount { get; set; }
    public byte[]? SBox { get; set; }

    private byte[] RotateWord(byte[] word)
    {
        byte tmp = word[0];

        for (int i = 0; i < 3; i++)
            word[i] = word[i + 1];

        word[3] = tmp;

        return word;
    }

    byte[] SubByte(byte[] vec)
    {
        if (SBox == null)
        {
            throw new NullReferenceException();
        }

        byte[] res = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            res[i] = SBox[vec[i]];
        }

        return res;
    }

    byte RCon(int i, int t)
    {
        ushort res = 0xcb;
        for (int ind = 0; ind < i + 1; ind++)
        {
            res <<= 1;
            if (res > 0xff)
            {
                res ^= (ushort)((1 << 8) | Mod);
            }
        }

        if (t == 0)
        {
            return (byte)res;
        }
        else
        {
            return 0;
        }
    }


    public byte[,] KeyExpansion(byte[] key)
    {
        int nb = BlockLength / 4;
        int nk = key.Length / 4;
        int nr = RoundsCount;

        byte[,] w = new byte[nb * (nr + 1), 4];
        byte[] temp = new byte[4];

        for (int i = 0; i < nk; i++)
        {
            w[i, 0] = key[4 * i];
            w[i, 1] = key[4 * i + 1];
            w[i, 2] = key[4 * i + 2];
            w[i, 3] = key[4 * i + 3];
        }

        for (int i = nk; i < (nb * (nr + 1)); i++)
        {
            for (int t = 0; t < 4; t++)
                temp[t] = w[i - 1, t];

            if (i % nk == 0)
            {
                temp = SubByte(RotateWord(temp));
                for (int t = 0; t < 4; t++)
                    temp[t] ^= RCon(i / nk, t);
            }
            else if (nk > 6 && i % nk == 4)
            {
                temp = SubByte(temp);
            }

            for (int t = 0; t < 4; t++)
                w[i, t] = (byte)(w[i - nk, t] ^ temp[t]);
        }

        return w;
    }

    public byte[][] ExpandKey(byte[] key)
    {
        byte[,] tmpRes = KeyExpansion(key);
        byte[][] res = new byte[RoundsCount + 1][];

        for (int i = 0; i < tmpRes.Length / 4; i++)
        {
            if ((i * 4) % BlockLength == 0)
            {
                res[(i * 4) / BlockLength] = new byte[BlockLength];
            }

            for (int j = 0; j < 4; j++)
            {
                res[(i * 4) / BlockLength][(i * 4 + j) % BlockLength] = tmpRes[i, j];
            }
        }

        return res;
    }
}