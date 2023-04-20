namespace Cryptography_Laba_1;

public interface IEncrypting
{
    byte[] Encrypt(byte[] data);
    byte[] Decrypt(byte[] data);
    void SetKey(byte[] key);
}