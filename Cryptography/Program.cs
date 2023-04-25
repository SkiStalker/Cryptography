using Cipher;

namespace Cryptography;

public static class Program
{
    private static void Main()
    {
        byte[] rijndaelKey = Cipher.Cipher.GenerateKey(256);
        byte[] rijndaelInitVector = Cipher.Cipher.GenerateInitVector(192);

        byte[] desKey = Cipher.Cipher.GenerateKey(64);
        byte[] desInitVector = Cipher.Cipher.GenerateInitVector(64);

        byte[] data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

        Cipher.Cipher rijndaelCipher = new Cipher.Cipher(rijndaelKey, 192
            , Cipher.Cipher.AlgorithmType.Rijndael, Cipher.Cipher.CryptRule.RDH,
            Cipher.Cipher.PaddingType.PKCS7, rijndaelInitVector);

        Cipher.Cipher desCipher = new Cipher.Cipher(desKey, 64, Cipher.Cipher.AlgorithmType.DES, Cipher.Cipher.CryptRule.CTR,
            Cipher.Cipher.PaddingType.ISO_10126, desInitVector);


        rijndaelCipher.Encrypt(data, out byte[] res);

        desCipher.Encrypt(res, out byte[] desRes);

        desCipher.Decrypt(desRes, out byte[] desDecryptData);

        rijndaelCipher.Decrypt(desDecryptData, out byte[] decryptData);

        Console.WriteLine(Convert.ToHexString(decryptData));
        Console.ReadLine();
    }
}