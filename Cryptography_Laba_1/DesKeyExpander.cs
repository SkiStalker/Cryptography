namespace Cryptography_Laba_1;

public class DesKeyExpander : IKeyExpanding
{
    private static readonly byte[] suppressKeyTable = new byte[]
    {
        14, 17, 11, 24, 01, 05, 03, 28,
        15, 06, 21, 10, 23, 19, 12, 04,
        26, 08, 16, 07, 27, 20, 13, 02,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
    };

    private static readonly byte[] removeEvenBitsTable = new byte[]
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