using System.Numerics;

namespace Rsa;

public interface IPrimaryTest
{
    public bool Test(BigInteger d, double primaryProbability);
}