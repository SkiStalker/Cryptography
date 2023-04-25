using Block_Cryptography_Algorithm;

namespace Des;

public class FeistelNetwork : IEncrypting
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