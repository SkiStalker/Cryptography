using Cryptography_Laba_1;

namespace Cryptography_Laba_2
{
    public class RijndaelRoundEncryptor : IRoundEncrypting
    {
        public bool LastRound { get; set; }
        public byte[] SubBytes { get; init; }

        public byte[] MixColumnsPolynomial { get; init; }

        public byte[] GetShiftValues(int blockLength)
        {
            int nb = blockLength / 4;
            if (nb == 4 || nb == 6)
            {
                return new byte[] { 1, 2, 3 };
            }
            else if (nb == 8)
            {
                return new byte[] { 1, 3, 4 };
            }
            else
            {
                throw new ArgumentException("Incorrect block length");
            }
        }

        private byte[] MixColumns(byte[] state)
        {

            byte[] res = new byte[state.Length];
            byte mod = 0b10001;
            Polynomial pol = new Polynomial();

            for (int i = 0; i < state.Length / 4; i++)
            {
                res[i] = (byte)(pol.MultPolynomials(state[i * 4], MixColumnsPolynomial[3], mod) ^
                                pol.MultPolynomials(state[i * 4 + 1], MixColumnsPolynomial[0], mod) ^
                                pol.MultPolynomials(state[i * 4 + 2], MixColumnsPolynomial[1], mod) ^
                                pol.MultPolynomials(state[i * 4 + 3], MixColumnsPolynomial[2], mod));
                
                res[i] = (byte)(pol.MultPolynomials(state[i * 4], MixColumnsPolynomial[2], mod) ^
                                pol.MultPolynomials(state[i * 4 + 1], MixColumnsPolynomial[3], mod) ^
                                pol.MultPolynomials(state[i * 4 + 2], MixColumnsPolynomial[0], mod) ^
                                pol.MultPolynomials(state[i * 4 + 3], MixColumnsPolynomial[1], mod));
                
                res[i] = (byte)(pol.MultPolynomials(state[i * 4], MixColumnsPolynomial[1], mod) ^
                                pol.MultPolynomials(state[i * 4 + 1], MixColumnsPolynomial[2], mod) ^
                                pol.MultPolynomials(state[i * 4 + 2], MixColumnsPolynomial[3], mod) ^
                                pol.MultPolynomials(state[i * 4 + 3], MixColumnsPolynomial[0], mod));
                
                res[i] = (byte)(pol.MultPolynomials(state[i * 4], MixColumnsPolynomial[0], mod) ^
                                pol.MultPolynomials(state[i * 4 + 1], MixColumnsPolynomial[1], mod) ^
                                pol.MultPolynomials(state[i * 4 + 2], MixColumnsPolynomial[2], mod) ^
                                pol.MultPolynomials(state[i * 4 + 3], MixColumnsPolynomial[3], mod));
            }

            return res;
        }

        public byte[] RoundEncrypt(byte[] data, byte[] roundKey)
        {
            byte[] c = GetShiftValues(data.Length);

            byte[] res = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                res[i] = SubBytes[data[i]];
            }

            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < c[i]; k++)
                    {
                        byte t = res[i * 4];
                        res[j * 4 + i] = res[(i + 1) * 4];
                        res[(j + 1) * 4 + i] = res[(i + 2) * 4];
                        res[(j + 2) * 4 + i] = res[(i + 3) * 4];
                        res[(j + 3) * 4 + i] = t;
                    }
                }
            }

            if (!LastRound)
            {
                res = MixColumns(res);
            }
            return res;
        }
    }

    static class Program
    {
        static byte[] GetInverseSMatrix(byte mod)
        {
            Polynomial pol = new Polynomial();
            byte[] res = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                byte tmp = (byte)i;
                tmp = (byte)(CycleLeftShift(tmp, 1) ^ CycleLeftShift(tmp, 3) ^
                             CycleLeftShift(tmp, 6) ^ 0x05);
                res[i] = pol.FindReverseElement(tmp, mod);
            }

            return res;
        }

        static byte[] GetSMatrix(byte mod)
        {
            Polynomial pol = new Polynomial();
            byte[] res = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                byte tmp = pol.FindReverseElement((byte)i, mod);
                res[i] = (byte)(tmp ^ CycleLeftShift(tmp, 1) ^ CycleLeftShift(tmp, 2) ^
                                CycleLeftShift(tmp, 3) ^ CycleLeftShift(tmp, 4) ^ 0x63);
            }

            return res;
        }

        static byte CycleLeftShift(byte d, byte cnt)
        {
            return (byte)((d << cnt) | (d >> (8 - cnt)));
        }

        private static byte[][] nrTable = new byte[][]
        {
            new byte[] { 10, 12, 14 },
            new byte[] { 12, 12, 14 },
            new byte[] { 14, 14, 14 }
        };

        static byte GetRoundsCount(byte blockLength, byte keyLength)
        {
            int nb = blockLength / 4;
            int nk = keyLength / 4;
            return nrTable[nb / 2 - 2][nk / 2 - 2];
        }

        static void Main()
        {
            byte[] arr = new Polynomial().GetIrreduciblePolynomials();
            int a = 12;
        }
    }
}