using Cryptography_Laba_1;

namespace Cryptography_Laba_2
{
    public class RijndaelKeyExpanded : IKeyExpanding
    {
        public byte Mod { get; set; }
        public byte BlockLength { get; set; }
        byte[] RotateLeft(byte[] vec)
        {
            byte[] res = new byte[vec.Length];
            for (int i = 0; i < 4; i++)
            {
                res[i] = res[(i + 1) % vec.Length];
            }

            return res;
        }
        
        public byte[] RCon(int i)
        {
            ushort res = 0xcb;
            for (int ind = 0; ind < i + 1; ind++)
            {
                res <<= 1;
                if (res > 0xff)
                {
                    res ^= (ushort)((1 << 8) | Mod);
                }
            }

            return new byte[] { (byte)res, 0, 0, 0 };
        }
        public byte[][] ExpandKey(byte[] key)
        {
            return new byte[0][];

        }
    }

    static class Program
    {
        static byte[] GetInverseSMatrix(byte mod)
        {
            Polynomial pol = new Polynomial();
            byte[] res = new byte[256];
            for (int i = 0; i < 256; i++)
            {

                byte tmp = (byte)i;
                tmp = (byte)(CycleLeftShift(tmp, 1) ^ CycleLeftShift(tmp, 3) ^
                             CycleLeftShift(tmp, 6) ^ 0x05);
                res[i] = pol.FindReverseElement(tmp, mod);
            }

            return res;
        }

        static byte[] GetSMatrix(byte mod)
        {
            Polynomial pol = new Polynomial();
            byte[] res = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                byte tmp = pol.FindReverseElement((byte)i, mod);
                res[i]= (byte)(tmp ^ CycleLeftShift(tmp, 1) ^ CycleLeftShift(tmp, 2) ^
                                             CycleLeftShift(tmp, 3) ^ CycleLeftShift(tmp, 4) ^ 0x63);
            }

            return res;
        }

        static byte CycleLeftShift(byte d, byte cnt)
        {
            return (byte)((d << cnt) | (d >> (8 - cnt)));
        }

        static void Main()
        {
            RijndaelKeyExpanded r = new RijndaelKeyExpanded
            {
                Mod = new Polynomial().GetStandardIrreduciblePolynomial()
            };
            byte[] res = r.RCon(1);
            int a = 12;
        }
    }
}