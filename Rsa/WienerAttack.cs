using System.Numerics;

namespace Rsa;

public static class WienerAttack
{
    public static BigInteger? MakeAttack(BigInteger e, BigInteger n)
    {
        List<BigInteger> chain = GetFractionChain(e, n);
        List<(BigInteger, BigInteger)> fractions = GetSuitFractions(chain);
        
        
        foreach ((BigInteger, BigInteger) frac in fractions)
        {
            RSA rsa = new RSA(1, RSA.PrimaryTest.MillerRabin, 0.5);
            BigInteger data = rsa.Encrypt(12345, e, n);
            if (rsa.Decrypt(data, frac.Item2, n) == 12345)
            {
                return frac.Item2;
            }
        }

        return null;
    }


    public static List<(BigInteger, BigInteger)> GetSuitFractions(List<BigInteger> x)
    {
        List<(BigInteger, BigInteger)> values = new List<(BigInteger, BigInteger)>();

        BigInteger p0 = 1;
        BigInteger q0 = 0;
        BigInteger p1 = x[0];
        BigInteger q1 = 1;
        int n = x.Count;

        for (int i = 1; i < n; i++)
        {
            BigInteger pi = p1 * x[i] + p0;
            BigInteger qi = q1 * x[i] + q0;
            values.Add((pi, qi));
            p0 = p1;
            q0 = q1;
            p1 = pi;
            q1 = qi;
        }

        return values;
    }

    public static List<BigInteger> GetFractionChain(BigInteger e, BigInteger N)
    {
        List<BigInteger> chain = new List<BigInteger>();

        BigInteger tempE = e;
        BigInteger tempN = N;
        BigInteger rem = tempE / tempN;

        chain.Add(rem);

        while (tempE != 0)
        {
            (tempE, tempN) = (tempN, tempE);
            rem = tempE / tempN;
            chain.Add(rem);
            tempE %= tempN;
        }

        return chain;
    }
}