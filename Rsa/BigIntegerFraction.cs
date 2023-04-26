using System.Numerics;

namespace Rsa;

public class BigIntegerFraction: ICloneable
{
    public BigInteger Divisible { get; private set; }
    public BigInteger Divider { get; private set; }


    public int Sign => Divisible.Sign;

    public BigIntegerFraction(BigInteger divisible, BigInteger divider)
    {
        this.Divisible = divisible;
        this.Divider = divider;
    }

    public static implicit operator BigIntegerFraction(BigInteger d)
    {
        return new BigIntegerFraction(d, 1);
    }

    public static BigIntegerFraction operator +(BigIntegerFraction frac, BigInteger d)
    {
        return new BigIntegerFraction(frac.Divisible + d * frac.Divider, frac.Divider);
    }

    public static BigIntegerFraction operator +(BigIntegerFraction fracLeft, BigIntegerFraction fracRight)
    {
        if (fracLeft.Divider == fracRight.Divider)
        {
            return new BigIntegerFraction(fracLeft.Divisible + fracRight.Divisible, fracLeft.Divider);
        }
        else
        {
            return new BigIntegerFraction(
                fracLeft.Divisible * fracRight.Divider + fracRight.Divisible * fracLeft.Divider,
                fracLeft.Divider * fracRight.Divider);
        }
    }

    public static BigIntegerFraction operator -(BigIntegerFraction frac)
    {
        return new BigIntegerFraction(-frac.Divisible, frac.Divider);
    }

    public static BigIntegerFraction operator -(BigIntegerFraction frac, BigInteger d)
    {
        return frac + (-d);
    }

    public static BigIntegerFraction operator -(BigIntegerFraction fracLeft, BigIntegerFraction fracRight)
    {
        return fracLeft + (-fracRight);
    }

    public static BigIntegerFraction operator *(BigIntegerFraction fracLeft, BigIntegerFraction fracRight)
    {
        return new BigIntegerFraction(fracLeft.Divisible * fracRight.Divisible, 
            fracLeft.Divider * fracRight.Divider);
    }

    public static BigIntegerFraction operator /(BigIntegerFraction fracLeft, BigIntegerFraction fracRight)
    {
        return new BigIntegerFraction(fracLeft.Divisible * fracRight.Divider, 
            fracLeft.Divider * fracRight.Divisible);
    }

    public BigInteger Divide()
    {
        return Divisible / Divider;
    }

    public static BigIntegerFraction operator^(BigIntegerFraction d, int p)
    {
        return new BigIntegerFraction(d.Divider, d.Divisible);
    }
    
    public object Clone()
    {
        return new BigIntegerFraction(this.Divisible, this.Divider);
    }
}