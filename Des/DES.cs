namespace Des;

public sealed class DES : FeistelNetwork
{
    private static readonly byte[] StartPermBlock = new byte[]
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

    private static readonly byte[] EndPermBlock = new byte[]
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

    public DES(byte[] key) : base(new DesKeyExpander(), new DesRoundEncryptor())
    {
        SetKey(key);
    }

    private byte[] Crypt(byte[] data, bool encrypt)
    {
        byte[] res = new byte[data.Length];
        data.CopyTo(res, 0);
        PBlock(ref res, StartPermBlock);
        res = encrypt ? base.Encrypt(res) : base.Decrypt(res);
        PBlock(ref res, EndPermBlock);
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