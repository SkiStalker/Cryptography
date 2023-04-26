using System.Numerics;
using System.Security.Cryptography;

namespace Rsa;

public class RSA
{
    private readonly uint keysBitLength;
    private readonly PrimaryTest primaryTest;
    private readonly double primaryProbability;

    public enum PrimaryTest
    {
        Fermat,
        SolovayStrassen,
        MillerRabin
    }

    public RSA(uint keysBitLength, PrimaryTest primaryTest, double primaryProbability)
    {
        this.primaryTest = primaryTest;
        this.primaryProbability = primaryProbability;
        this.keysBitLength = keysBitLength;
    }

    private void GeneratePrimaryDigit(ref BigInteger? primaryDigit, ref bool findPrimary, Semaphore semRes,
        Mutex mutexRes, double keyLengthCoefficient = 1)
    {
        IPrimaryTest? primaryTestImplementation = null;
        switch (primaryTest)
        {
            case PrimaryTest.Fermat:
            {
                primaryTestImplementation = new FermatTest();
                break;
            }
            case PrimaryTest.SolovayStrassen:
            {
                primaryTestImplementation = new SolovayStrassenTest();
                break;
            }
            case PrimaryTest.MillerRabin:
            {
                primaryTestImplementation = new MillerRabinTest();
                break;
            }
            default:
            {
                throw new ArgumentException("Unknown primary test");
            }
        }

        byte[] tmpBytes = new byte[(uint)(keysBitLength * keyLengthCoefficient) / 8];
        RandomNumberGenerator generator = RandomNumberGenerator.Create();
        generator.GetNonZeroBytes(tmpBytes);
        BigInteger tmpPrimary = new BigInteger(tmpBytes, true);
        BigInteger necessaryDigit = BigInteger.Pow(2, (int)(keysBitLength * keyLengthCoefficient));
        if (tmpPrimary < necessaryDigit)
        {
            tmpPrimary |= necessaryDigit;
        }

        if (tmpPrimary.IsEven)
        {
            tmpPrimary += BigInteger.One;
        }

        bool alive = true;
        while (alive)
        {
            mutexRes.WaitOne();
            alive = !findPrimary;
            mutexRes.ReleaseMutex();
            if (findPrimary)
            {
                continue;
            }

            if (primaryTestImplementation.Test(tmpPrimary, primaryProbability))
            {
                mutexRes.WaitOne();
                if (!findPrimary)
                {
                    primaryDigit = tmpPrimary;
                    findPrimary = true;
                }

                mutexRes.ReleaseMutex();
                break;
            }
            else
            {
                tmpPrimary += 2;

                if (tmpPrimary % 5 == 0)
                {
                    tmpPrimary += 2;
                }
            }
        }

        semRes.Release();
    }

    public Keys GenerateKeys()
    {
        BigInteger? p = null;
        BigInteger? q = null;
        int threadsCnt = Environment.ProcessorCount;


        bool findP = false;
        bool findQ = false;
        Semaphore semP = new Semaphore(0, threadsCnt);
        Semaphore semQ = new Semaphore(0, threadsCnt);
        Mutex mutexP = new Mutex(false);
        Mutex mutexQ = new Mutex(false);

        for (int i = 0; i < threadsCnt; i++)
        {
            new Thread(() => { GeneratePrimaryDigit(ref p, ref findP, semP, mutexP); }).Start();
        }

        for (int i = 0; i < threadsCnt; i++)
        {
            new Thread(() => { GeneratePrimaryDigit(ref q, ref findQ, semQ, mutexQ); }).Start();
        }

        for (int i = 0; i < threadsCnt; i++)
        {
            semP.WaitOne();
        }

        for (int i = 0; i < threadsCnt; i++)
        {
            semQ.WaitOne();
        }

        if (p == null || q == null)
        {
            throw new NullReferenceException();
        }

        if (p == null || q == null)
        {
            throw new NullReferenceException();
        }
        
        
        // Fermat defence (because using strong randomly generator)
        BigInteger n = p.Value * q.Value;

        BigInteger euler = (p.Value - BigInteger.One) * (q.Value - BigInteger.One);

        bool correctE = false;
        BigInteger? e = null;

        while (!correctE)
        {
            Semaphore semE = new Semaphore(0, threadsCnt);
            Mutex mutexE = new Mutex(false);
            bool findE = false;
            for (int i = 0; i < threadsCnt; i++)
            {
                new Thread(() => { GeneratePrimaryDigit(ref e, ref findE, semE, mutexE, 1.5); }).Start();
            }

            if (e == null)
            {
                throw new NullReferenceException();
            }

            for (int i = 0; i < threadsCnt; i++)
            {
                semE.WaitOne();
            }

            if (e.Value > (euler - BigInteger.One))
            {
                continue;
            }

            if (BigInteger.GreatestCommonDivisor(e.Value, euler) == BigInteger.One)
            {
                correctE = true;
                BigInteger tmpE = e.Value;
                
                // Wiener defence
                BigInteger n32 = BigIntegerTools.Sqrt(n * n * n);
                if (tmpE <= n32)
                {
                    BigInteger k = (n32 - tmpE) / euler;
                    tmpE += (k + 1)*euler;
                }

                e = tmpE;
            }
        }

        if (e == null)
        {
            throw new NullReferenceException();
        }

        BigInteger? nullableD = null;
        BigInteger? y = null;
        BigInteger gc = BigIntegerTools.GCDEx(e.Value, euler, ref nullableD, ref y);

        if (nullableD == null)
        {
            throw new NullReferenceException();
        }

        BigInteger d = nullableD.Value;
        while (d < 0)
        {
            d += euler;
        }

        return new Keys
        {
            E = e.Value,
            D = d,
            N = n
        };
    }

    public class Keys
    {
        public BigInteger E { get; set; }
        public BigInteger D { get; set; }
        public BigInteger N { get; set; }
    }

    public BigInteger Encrypt(BigInteger msg, BigInteger e, BigInteger n)
    {
        return BigInteger.ModPow(msg, e, n);
    }

    public BigInteger Decrypt(BigInteger msg, BigInteger d, BigInteger n)
    {
        return BigInteger.ModPow(msg, d, n);
    }
}