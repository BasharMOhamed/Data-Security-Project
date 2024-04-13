using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int q;
            int A1 = 1;
            int A2 = 0;
            int A3 = baseN;
            int B1 = 0;
            int B2 = 1;
            int B3 = number;
            int temp;

            while (B3 > 1)
            {
                q = A3 / B3;

                temp = B1;
                B1 = A1 - q * B1;
                A1 = temp;

                temp = B2;
                B2 = A2 - q * B2;
                A2 = temp;

                temp = B3;
                B3 = A3 - q * B3;
                A3 = temp;


            }

            if (B3 == 1)
            {

                return (B2 + baseN * 1000) % baseN;
            }
            else
            {
                return -1;
            }


        }
    }
}