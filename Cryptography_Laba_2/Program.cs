namespace Cryptography_Laba_2
{
    class Polynomial
    {
        public byte AddPolynomials(byte left, byte right)
        {
            return (byte)(left ^ right);
        }

        byte FindPow(ushort pol)
        {
            byte pow = 0;
            while (pol != 0)
            {
                pow++;
                pol >>= 1;
            }

            return pow;
        }

        (byte, byte, byte) FindReverseElement(byte element, byte mod)
        {
            if (element == 0)
            {
                return (mod, 0, 1);
            }
            else
            {
                (byte div, byte x, byte y) = FindReverseElement((byte)(mod % element), element);
            }
        }
        
        public byte MultPolynomials(byte left, byte right, byte mod)
        {
            ushort mult = 0;
            for (int i = 0; i < 8; i++)
            {
                if (((left >> i) & 1) != 0)
                {
                    for (int j = 0; j < 8; j++)
                    {
                        mult |= (byte)(((left >> i) & (right >> j) & 1) << (i + j));
                    }
                }
            }

            byte remainder = 0;
            while (true)
            {
                byte pow = FindPow(mult);

                sbyte resPow = (sbyte)(pow - 8);

                if (resPow < 0)
                {
                    break;
                }
                else
                {
                    remainder |= (byte)(1 << resPow);
                    mult = (ushort)(mult & ~(1 << pow));
                    for (int i = 0; i < 8; i++)
                    {
                        mult = (ushort)((mult & ~(1 << (i + resPow))) | (((mult >> (i + resPow) & 1) ^ ((mod >> i) & 1))<<(i + resPow)));
                    }
                }
            }

            return remainder;
        }
    }

    static class Program
    {
        static void Main()
        {
            Console.WriteLine("Hello, World!");
        }
    }
}