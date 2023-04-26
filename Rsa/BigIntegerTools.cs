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

    public static BigInteger GcdEx(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
    {
        if (b < a)
        {
            (a, b) = (b, a);
        }
    
        if (a == 0)
        {
            x = 0;
            y = 1;
            return b;
        }
 
        BigInteger gcd = GcdEx(b % a, a, out x, out y);
    
        BigInteger newY = x;
        BigInteger newX = y - (b / a) * x;
    
        x = newX;
        y = newY;
        return gcd;
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