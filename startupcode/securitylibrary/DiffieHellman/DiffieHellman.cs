using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        int calcKey(int basee, int exponent, int mod)
        {
            int result = 1;

            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                {
                    result = (result * basee) % mod;
                }
                basee = (basee * basee) % mod;
                exponent = exponent / 2;
            }
            return result;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            List<int> keys = new List<int>();
            int fstKey = calcKey(alpha, xa, q);

            int secKey = calcKey(alpha, xb, q);

            int res1 = calcKey(secKey, xa, q);
            keys.Add(res1);

            int res2 = calcKey(fstKey, xb, q);
            keys.Add(res2);
            return keys;
        }
    }
}
