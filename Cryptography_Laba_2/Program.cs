using Cryptography_Laba_1;

namespace Cryptography_Laba_2
{
    public static class Program
    {
        public static byte[] UIntToByteArr(uint val)
        {
            return new byte[]
            {
                (byte)(val >> 24 & 0b11111111), (byte)(val >> 16 & 0b11111111), (byte)(val >> 8 & 0b11111111),
                (byte)(val >> 0 & 0b11111111)
            };
        }


        public static void PrintState(byte[] state)
        {
            string view = Convert.ToHexString(state);
            for (int i = 0; i < view.Length; i++)
            {
                if (i % 4 == 0)
                {
                    Console.WriteLine();
                }

                if (i % 2 == 0)
                {
                    Console.Write(" ");
                }

                Console.Write(view[i]);
            }
        }

        static void Main()
        {
            byte[] rijndaelKey = Cipher.GenerateKey(256);
            byte[] rijndaelInitVector = Cipher.GenerateInitVector(192);
            
            byte[] desKey = Cipher.GenerateKey(64);
            byte[] desInitVector = Cipher.GenerateInitVector(64);

            byte[] data = new byte[]{0, 1, 2, 3, 4, 5, 6, 7 ,8, 9 ,10, 11, 12, 13, 14, 15};

            Cipher rijndaelCipher = new Cipher(rijndaelKey, 192
                
                , Cipher.AlgorithmType.Rijndael, Cipher.CryptRule.RDH,
                Cipher.PaddingType.PKCS7, rijndaelInitVector);

            Cipher desCipher = new Cipher(desKey, 64, Cipher.AlgorithmType.DES, Cipher.CryptRule.CTR,
                Cipher.PaddingType.ISO_10126, desInitVector);
            

            rijndaelCipher.Encrypt(data, out byte[] res);
            
            desCipher.Encrypt(res, out byte[] desRes);
            
            desCipher.Decrypt(desRes, out byte[] desDecryptData);

            rijndaelCipher.Decrypt(desDecryptData, out byte[] decryptData);

            Console.WriteLine(Convert.ToHexString(decryptData));
            Console.ReadLine();
        }
    }
}