using Block_Cryptography_Algorithm;

namespace Rijndael;

public sealed class Rijndael : IEncrypting
{
    private readonly IKeyExpanding keyExpander;
    private readonly IRoundEncrypting roundEncryptor;
    private byte[]? key;
    public int RoundsCount { get; init; }
    public int BlockLength { get; init; }

    public Rijndael(byte[] key)
    {
        keyExpander = new RijndaelKeyExpanded();
        roundEncryptor = new RijndaelRoundEncryptor();
        this.key = key;
    }
    
    public static byte GetInverseSMatrixElement(byte d, byte mod)
    {
        Polynomial pol = new Polynomial();
        byte tmp = d;
        tmp = (byte)(CycleLeftShift(tmp, 1) ^ CycleLeftShift(tmp, 3) ^
                     CycleLeftShift(tmp, 6) ^ 0x05);
        return pol.FindReverseElement(tmp, mod);
    }

    public static byte[] GetInverseSMatrix(byte mod)
    {
        Polynomial pol = new Polynomial();
        byte[] res = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            byte tmp = (byte)i;
            tmp = (byte)(CycleLeftShift(tmp, 1) ^ CycleLeftShift(tmp, 3) ^
                         CycleLeftShift(tmp, 6) ^ 0x05);
            res[i] = pol.FindReverseElement(tmp, mod);
        }

        return res;
    }

    public static byte GetSMatrixElement(byte d, byte mod)
    {
        Polynomial pol = new Polynomial();
        byte tmp = pol.FindReverseElement((byte)d, mod);
        return (byte)(tmp ^ CycleLeftShift(tmp, 1) ^ CycleLeftShift(tmp, 2) ^
                      CycleLeftShift(tmp, 3) ^ CycleLeftShift(tmp, 4) ^ 0x63);
    }

    public static byte[] GetSMatrix(byte mod)
    {
        Polynomial pol = new Polynomial();
        byte[] res = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            byte tmp = pol.FindReverseElement((byte)i, mod);
            res[i] =  (byte)(tmp ^ CycleLeftShift(tmp, 1) ^ CycleLeftShift(tmp, 2) ^
                          CycleLeftShift(tmp, 3) ^ CycleLeftShift(tmp, 4) ^ 0x63);
        }

        return res;
    }

    static byte CycleLeftShift(byte d, byte cnt)
    {
        return (byte)((d << cnt) | (d >> (8 - cnt)));
    }

    private static readonly byte[][] NrTable = new byte[][]
    {
        new byte[] { 10, 12, 14 },
        new byte[] { 12, 12, 14 },
        new byte[] { 14, 14, 14 }
    };

    public static byte GetRoundsCount(int blockLength, int keyLength)
    {
        int nb = blockLength / 4;
        int nk = keyLength / 4;
        return NrTable[nb / 2 - 2][nk / 2 - 2];
    }
    

    public Rijndael(IKeyExpanding keyExpander, IRoundEncrypting roundEncryptor)
    {
        this.keyExpander = keyExpander;
        this.roundEncryptor = roundEncryptor;
    }

    public byte[] Encrypt(byte[] data)
    {
        Polynomial pol = new Polynomial();
        RijndaelRoundEncryptor rijndaelRoundEncryptor = (RijndaelRoundEncryptor)roundEncryptor;
        rijndaelRoundEncryptor.RoundsCount = RoundsCount;
        rijndaelRoundEncryptor.Module = pol.GetStandardIrreduciblePolynomial();
        rijndaelRoundEncryptor.Encrypt = true;
        rijndaelRoundEncryptor.SBox = Rijndael.GetSMatrix(pol.GetStandardIrreduciblePolynomial());
        rijndaelRoundEncryptor.MixColumnsPolynomial = new byte[] { 3, 1, 1, 2 };


        RijndaelKeyExpanded rijndaelKeyExpanded = (RijndaelKeyExpanded)keyExpander;
        rijndaelKeyExpanded.RoundsCount = (byte)RoundsCount;
        rijndaelKeyExpanded.SBox = GetSMatrix(pol.GetStandardIrreduciblePolynomial());
        rijndaelKeyExpanded.Mod = pol.GetStandardIrreduciblePolynomial();
        rijndaelKeyExpanded.BlockLength = BlockLength;
        
        
        
        byte[] res = new byte[data.Length];
        byte[][] roundKeys =
            keyExpander.ExpandKey(key ?? throw new NullReferenceException("Cipher key null reference"));
        

        for (int i = 0; i < data.Length; i++)
        {
            res[i] = (byte)(data[i] ^ roundKeys[0][i]);
        }
        for (int i = 0; i < RoundsCount; i++)
        {
            res = roundEncryptor.RoundEncrypt(res, roundKeys[i + 1]);
        }

        return res;
    }

    public byte[] Decrypt(byte[] data)
    {
        Polynomial pol = new Polynomial();
        RijndaelRoundEncryptor rijndaelRoundEncryptor = (RijndaelRoundEncryptor)roundEncryptor;
        rijndaelRoundEncryptor.RoundsCount = RoundsCount;
        rijndaelRoundEncryptor.Module = pol.GetStandardIrreduciblePolynomial();
        rijndaelRoundEncryptor.Encrypt = false;
        rijndaelRoundEncryptor.SBox = Rijndael.GetInverseSMatrix(pol.GetStandardIrreduciblePolynomial());
        rijndaelRoundEncryptor.MixColumnsPolynomial = new byte[] { 11, 13, 9, 14 };


        RijndaelKeyExpanded rijndaelKeyExpanded = (RijndaelKeyExpanded)keyExpander;
        rijndaelKeyExpanded.RoundsCount = (byte)RoundsCount;
        rijndaelKeyExpanded.SBox = GetSMatrix(pol.GetStandardIrreduciblePolynomial());
        rijndaelKeyExpanded.Mod = pol.GetStandardIrreduciblePolynomial();
        rijndaelKeyExpanded.BlockLength = BlockLength;
        
        
        byte[] res = new byte[data.Length];
        data.CopyTo(res, 0);
        byte[][] roundKeys =
            keyExpander.ExpandKey(key ?? throw new NullReferenceException("Cipher key null reference"));

        for (int i = 0; i < RoundsCount; i++)
        {
            res = roundEncryptor.RoundEncrypt(res, roundKeys[RoundsCount - i]);
        }

        for (int i = 0; i < res.Length; i++)
        {
            res[i] = (byte)(res[i] ^ roundKeys[0][i]);
        }

        return res;
    }

    public void SetKey(byte[] cipherKey)
    {
        this.key = cipherKey;
    }
}