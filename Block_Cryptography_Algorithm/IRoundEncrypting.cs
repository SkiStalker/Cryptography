namespace Block_Cryptography_Algorithm;

public interface IRoundEncrypting
{
    byte[] RoundEncrypt(byte[] data, byte[] roundKey);
}