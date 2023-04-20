using System.Net.Security;

namespace Test_Cryptography_Laba_2;

using Cryptography_Laba_2;

public class Tests
{
    private Polynomial polynomial;

    [SetUp]
    public void Setup()
    {
        polynomial = new Polynomial();
    }

    [Test]
    public void Mult_Test1()
    {
        Assert.That(polynomial.MultPolynomials(113, 204, polynomial.GetStandardIrreduciblePolynomial()),
            Is.EqualTo(155));
    }

    [Test]
    public void Mult_Test2()
    {
        Assert.That(polynomial.MultPolynomials(0b01010111, 0b10000011, polynomial.GetStandardIrreduciblePolynomial()),
            Is.EqualTo(0b11000001));
    }

    [Test]
    public void Mult_Test3()
    {
        Assert.That(polynomial.MultPolynomials(87, 131, polynomial.GetStandardIrreduciblePolynomial()),
            Is.EqualTo(0b11000001));
    }

    [Test]
    public void Inverse_Test1()
    {
        byte d = 101;
        Assert.That(
            polynomial.MultPolynomials(d,
                polynomial.FindReverseElement(d, polynomial.GetStandardIrreduciblePolynomial()),
                polynomial.GetStandardIrreduciblePolynomial()),
            Is.EqualTo(1));
    }
    [Test]
    public void Inverse_Test2()
    {
        byte d = 0x63;
        Assert.That(
            polynomial.MultPolynomials(d,
                polynomial.FindReverseElement(d, polynomial.GetStandardIrreduciblePolynomial()),
                polynomial.GetStandardIrreduciblePolynomial()),
            Is.EqualTo(1));
    }
}