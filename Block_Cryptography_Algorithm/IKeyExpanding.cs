namespace Block_Cryptography_Algorithm;

public interface IKeyExpanding
{
    byte[][] ExpandKey(byte[] key);
}