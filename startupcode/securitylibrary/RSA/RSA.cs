using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Modulus(int Base, int expo, int n)
        {
            int result = 1;
            for (int i = 0; i < expo; i++)
            {
                result = (Base * result) % n;
            }
            return result;

        }


        public int Encrypt(int p, int q, int M, int e)
        {

            int n = p * q;
            return Modulus(M, e, n);

        }

        public int Decrypt(int p, int q, int C, int e)
        {

            int n = p * q;
            ExtendedEuclid extendedEuclid = new ExtendedEuclid();
            int euclideanQ = (p - 1) * (q - 1);
            int d = extendedEuclid.GetMultiplicativeInverse(e, euclideanQ);
            return Modulus(C, d, n);

        }
    }
}