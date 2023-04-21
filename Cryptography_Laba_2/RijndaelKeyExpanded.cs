using Cryptography_Laba_1;

namespace Cryptography_Laba_2;

public class RijndaelKeyExpanded : IKeyExpanding
{
    public byte Mod { get; init; }
    public byte BlockLength { get; init; }
    public byte RoundsCount { get; init; }
    public byte[] SubBytes { get; init; }

    uint RotateLeft(uint vec)
    {
        return (vec << 8) | (vec >> (32 - 8));
    }

    uint SubByte(uint vec)
    {
        uint res = 0;
        for (int i = 0; i < 4; i++)
        {
            res |= (uint)(SubBytes[(byte)(res >> (8 * i) & 0b11111111)] << (8 * i));
        }

        return res;
    }

    uint RCon(int i)
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

        return (uint)(res << 24);
    }

    public byte[][] ExpandKey(byte[] key)
    {
        int nk = key.Length / 4;
        int nb = BlockLength / 4;

        uint[] w = new uint[nb * (RoundsCount + 1)];

        for (int i = 0; i < nk; i++)
        {
            int iKey = i * 4;
            w[i] = (uint)(key[iKey] | (key[iKey + 1] << 8) | (key[iKey + 2] << 16) | (key[iKey + 3] << 24));
        }

        if (RoundsCount < 6)
        {
            for (int j = nk; j < nb * (nk + 1); j += nk)
            {
                w[j] = w[j - nk] ^ SubByte(RotateLeft(w[j - 1])) ^ RCon(j / nk);

                for (int i = 1; i < nk && i + j < nb * (RoundsCount + 1); i++)
                {
                    w[i + j] = w[i + j - nk] ^ w[i + j - 1];
                }
            }
        }
        else
        {
            for (int j = nk; j < nb * (nk + 1); j += nk)
            {
                w[j] = w[j - nk] ^ SubByte(RotateLeft(w[j - 1])) ^ RCon(j / nk);

                for (int i = 1; i < 4; i++)
                {
                    w[i + j] = w[i + j - nk] ^ w[i + j - 1];
                }

                w[j + 4] = w[j + 4 - nk] ^ SubByte(w[j + 3]);

                for (int i = 5; i < nk; i++)
                {
                    w[i + j] = w[i + j - nk] ^ w[i + j - 1];
                }
            }
        }

        byte[][] res = new byte[RoundsCount][];
        for (int i = 0; i < w.Length * 4; i++)
        {
            if (i % nb == 0)
            {
                res[i / nb] = new byte[nb];
            }

            res[i / nb][i % nb] = (byte)((w[i / nk] >> (8 * (i % nk))) & 0b11111111);
        }

        return res;
    }
}