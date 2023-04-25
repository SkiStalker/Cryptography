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
            Console.ReadLine();
        }
    }
}