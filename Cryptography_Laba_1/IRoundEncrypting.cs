namespace Cryptography_Laba_1;

public interface IRoundEncrypting
{
    byte[] RoundEncrypt(byte[] data, byte[] roundKey);
}