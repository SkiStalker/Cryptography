using System.Numerics;

namespace Rsa;

public static class BigIntegerTools
{
    public static BigInteger FastPower(BigInteger x, BigInteger n)
    {
        BigInteger result = BigInteger.One;
        while (n > 0)
        {
            if (n.IsEven)
            {
                x *= x;
                n /= 2;
            }
            else
            {
                result *= x;
                --n;
            }
        }

        return result;
    }

    public static BigInteger GCDEx(BigInteger a, BigInteger b, ref BigInteger? x, ref BigInteger? y)
    {
        if (a == BigInteger.Zero)
        {
            x = BigInteger.Zero;
            y = BigInteger.One;
            return b;
        }

        BigInteger? x1 = null;
        BigInteger? y1 = null;
        BigInteger d = GCDEx(b % a, a, ref x1, ref y1);
        if (x1 == null || y1 == null)
        {
            throw new NullReferenceException();
        }

        x = y1.Value - (b / a) * (x1.Value);
        y = x1;
        return d;
    }
    
    public static BigInteger Sqrt(BigInteger n)
    {
        if (n == 0) return 0;
        if (n > 0)
        {
            int bitLength = Convert.ToInt32(Math.Ceiling(BigInteger.Log(n, 2)));
            BigInteger root = BigInteger.One << (bitLength / 2);

            while (!IsSqrt(n, root))
            {
                root += n / root;
                root /= 2;
            }

            return root;
        }

        throw new ArithmeticException("NaN");
    }

    private static bool IsSqrt(BigInteger n, BigInteger root)
    {
        BigInteger lowerBound = root*root;
        BigInteger upperBound = (root + 1)*(root + 1);

        return (n >= lowerBound && n < upperBound);
    }
}