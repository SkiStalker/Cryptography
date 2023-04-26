using System.Numerics;

namespace Rsa;

public static class Program
{
    public static void Main()
    {
        List<List<BigInteger>> res = WienerAttack.MakeAttack(41, 91);
        Console.ReadLine();
    }
}