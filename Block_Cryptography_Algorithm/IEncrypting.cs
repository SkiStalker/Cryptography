﻿namespace Block_Cryptography_Algorithm;

public interface IEncrypting
{
    byte[] Encrypt(byte[] data);
    byte[] Decrypt(byte[] data);
    void SetKey(byte[] key);
}