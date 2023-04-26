using System.Numerics;
using Cipher;
using Rsa;

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
        
        Console.WriteLine($"Rijndael key : {Convert.ToHexString(rijndaelKey)}");
        Console.WriteLine($"Rijndael initial vector : {Convert.ToHexString(rijndaelInitVector)}");
        Console.WriteLine($"DES key : {Convert.ToHexString(desKey)}");
        Console.WriteLine($"DES initial vector : {Convert.ToHexString(desInitVector)}");
        
        Cipher.Cipher rijndaelCipher = new Cipher.Cipher(rijndaelKey, 192
            , Cipher.Cipher.AlgorithmType.Rijndael, Cipher.Cipher.CryptRule.RDH,
            Cipher.Cipher.PaddingType.PKCS7, rijndaelInitVector);

        Cipher.Cipher desCipher = new Cipher.Cipher(desKey, 64, Cipher.Cipher.AlgorithmType.DES, Cipher.Cipher.CryptRule.CTR,
            Cipher.Cipher.PaddingType.ISO_10126, desInitVector);

        
        Console.WriteLine($"Block algorithm raw data : {Convert.ToHexString(data)}");
        rijndaelCipher.Encrypt(data, out byte[] res);
        
        Console.WriteLine($"Rijndael encrypt data : {Convert.ToHexString(res)}");
        
        desCipher.Encrypt(res, out byte[] desRes);
        
        Console.WriteLine($"DES encrypt data : {Convert.ToHexString(desRes)}");
        
        desCipher.Decrypt(desRes, out byte[] desDecryptData);
        
        Console.WriteLine($"DES decrypt data : {Convert.ToHexString(desDecryptData)}");

        rijndaelCipher.Decrypt(desDecryptData, out byte[] decryptData);
        
        Console.WriteLine($"Rijndael decrypt data : {Convert.ToHexString(decryptData)}");

        RSA rsa = new RSA(128, RSA.PrimaryTest.MillerRabin, 0.9);

        RSA.Keys keys = rsa.GenerateKeys();
        
        Console.WriteLine($"RSA e : {keys.E}");
        Console.WriteLine($"RSA d : {keys.D}");
        Console.WriteLine($"RSA N : {keys.N}");
        
        BigInteger msg = 12345;
        Console.WriteLine($"RSA raw data : {msg}");

        BigInteger rsaRes =  rsa.Encrypt(msg, keys.E, keys.N);
        
        Console.WriteLine($"RSA encrypt data : {rsaRes}");

        BigInteger rsaDecrypt = rsa.Decrypt(rsaRes, keys.D, keys.N);
        
        Console.WriteLine($"RSA decrypt data : {rsaDecrypt}");

        BigInteger e = 1073780833;
        BigInteger n = 1220275921;
        
        Console.WriteLine($"Wiener attack e = {e}, N = {n}");
        
        BigInteger? d = WienerAttack.MakeAttack(e, n);

        if (d.HasValue)
        {
            Console.WriteLine($"Wiener attack d = {d.Value}");
        }
        else
        {
            Console.WriteLine($"Can not process Wiener attack");
        }
    }
}