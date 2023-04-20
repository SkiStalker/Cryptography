namespace Cryptography_Laba_2;

public class Polynomial
{
    public byte AddPolynomials(byte left, byte right)
    {
        return (byte)(left ^ right);
    }

    public byte[] GetIrreduciblePolynomials()
    {
        List<byte> res = new List<byte>();
        for (int i = 0; i < 256; i++)
        {
            if (IsIrreduciblePolynomial((byte)i))
            {
                res.Add((byte)i);
            }
        }

        return res.ToArray();
    }
        
    public bool IsIrreduciblePolynomial(byte pol)
    {
        ushort extPol = (ushort)(pol | (1 << 8));
        byte del = 2;
        while (del < 32)
        {
            ushort tmpPol = extPol;
            byte curPow = FindPow(del);
            while (true)
            {
                byte pow = FindPow(tmpPol);

                sbyte resPow = (sbyte)(pow - curPow);

                if (resPow < 0)
                {
                    break;
                }
                else
                {
                    tmpPol = (ushort)(tmpPol & ~(1 << pow));
                    for (int i = 0; i < curPow; i++)
                    {
                        tmpPol = (ushort)((tmpPol & ~(1 << (i + resPow))) |
                                          (((tmpPol >> (i + resPow) & 1) ^ ((del >> i) & 1)) << (i + resPow)));
                    }
                }
            }

            if (tmpPol == 0)
            {
                return false;
            }
            else
            {
                del += 1;
            }
        }

        return true;
    }

    public byte GetStandardIrreduciblePolynomial()
    {
        return 0b11011;
    }

    byte FindPow(ushort pol)
    {
        byte pow = 0;
        while (pol != 0)
        {
            pow++;
            pol >>= 1;
        }

        return (byte)(pow - 1);
    }

    public byte FastPow(byte d, int pow, byte mod)
    {
        if (pow == 0)
        {
            return 1;
        }
        else if (pow % 2 == 0)
        {
            return FastPow(MultPolynomials(d, d, mod), (byte)(pow / 2), mod);
        }
        else
        {
            return MultPolynomials(FastPow(MultPolynomials(d, d, mod), (byte)(pow / 2), mod),
                d, mod);
        }
    }

    public byte FindReverseElement(byte element, byte mod)
    {
        return FastPow(element, 254, mod);
    }

    public byte MultPolynomials(byte left, byte right, byte mod)
    {
        ushort mult = 0;
        for (int i = 0; i < 8; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                mult = (ushort)((mult & ~(1 << (i + j))) |
                                ((left >> i) & (right >> j) & 1 ^ (mult >> (i + j) & 1)) << (i + j));
            }
        }

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
                mult = (ushort)(mult & ~(1 << pow));
                for (int i = 0; i < 8; i++)
                {
                    mult = (ushort)((mult & ~(1 << (i + resPow))) |
                                    (((mult >> (i + resPow) & 1) ^ ((mod >> i) & 1)) << (i + resPow)));
                }
            }
        }

        return (byte)mult;
    }
}