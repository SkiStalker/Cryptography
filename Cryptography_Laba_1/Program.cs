namespace Cryptography_Laba_1
{
    internal static class Program
    {
        public static string PrintBits(byte[] arr)
        {
            string res = "";
            foreach (byte t in arr)
            {
                string tmp = Convert.ToString(t, 2);
                string pad = "";
                for (int j = 0; j < 8 - tmp.Length; j++)
                    pad += "0";

                res += pad + tmp;
            }

            return res;
        }

        private static void Main()
        {

            byte[] key = Cipher.GenerateKey();

            byte[] initVector = Cipher.GenerateInitVector();

            Cipher cipher = new Cipher(key, Cipher.CryptRule.RDH, initVector);
            Console.WriteLine($"Key: {Convert.ToHexString(key)}");
            Console.WriteLine($"Init vector: {Convert.ToHexString(initVector)}");
            cipher.Encrypt("C:\\Users\\79832\\Documents\\1.txt", "C:\\Users\\79832\\Documents\\1.crypt");
            
            cipher.Decrypt("C:\\Users\\79832\\Documents\\1.crypt", "C:\\Users\\79832\\Documents\\1.decrypt.txt");
            Console.WriteLine("Finished");
            Console.ReadLine();
        }
    }
}