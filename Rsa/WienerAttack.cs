using System.Numerics;

namespace Rsa;

public static class WienerAttack
{
    public static List<List<BigInteger>> MakeAttack(BigInteger e, BigInteger n)
    {
        try
        {


            List<List<BigInteger>> res = new List<List<BigInteger>>();

            BigIntegerFraction a = e / n;
            BigIntegerFraction x = new BigIntegerFraction(e, n) - a;

            BigIntegerFraction p1 = (BigInteger)1;
            BigIntegerFraction q1 = (BigInteger)0;

            BigIntegerFraction p = (BigIntegerFraction)a.Clone();
            BigIntegerFraction q = (BigInteger)1;
            
            List<BigInteger> tmpList = new List<BigInteger>();
            tmpList.AddRange(new BigInteger[] { p.Divide(), q.Divide() });
            res.Add(tmpList);
            
            while (e*q.Divide() % n != 1)
            {
                a = (x ^ -1).Divide();

                x = (x ^ -1) - a;

                BigIntegerFraction pn = a * p + p1;
                BigIntegerFraction qn = a * q + q1;

                p1 = p;
                q1 = q;

                p = pn;
                q = qn;
                if (q.Divide() == n)
                {
                    throw new ArgumentException();
                }
                tmpList = new List<BigInteger>();
                tmpList.AddRange(new BigInteger[] { p.Divide(), q.Divide() });
                res.Add(tmpList);
            }

            return res;
        }
        catch (Exception exception)
        {
            Console.WriteLine(exception);
            throw new ArgumentException("Can not make attack on this E and N keys");
        }
    }
}