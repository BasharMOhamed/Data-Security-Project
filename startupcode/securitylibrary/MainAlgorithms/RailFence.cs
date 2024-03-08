using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int key = 1;
            string CT = "";
            while (true)
            {
                CT = Encrypt(plainText, key);
                CT = CT.ToLower();
                if (CT.Equals(cipherText))
                {
                    return key;
                }
                key++;
                if (key == cipherText.Length)
                {
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string plainTxt = "";
            int count = 0;
            while (count < ((cipherText.Length / key) + (cipherText.Length % key != 0 ? 1 : 0)))
            {

                for (int i = count; i < cipherText.Length; i += ((cipherText.Length / key) + (cipherText.Length % key != 0 ? 1 : 0)))
                {
                    plainTxt += cipherText[i];
                }
                count++;
            }
            return plainTxt;
        }
        public static int IncrementUntilDivisible(int number, int divisor) // pt key 19   2
        {

            int counter = 0;
            int x = number;
            while (x % divisor != 0)
            {
                counter++;
                x++;
            }
            return counter;
        }

        public string Encrypt(string plainText, int key)
        {
            // throw new NotImplementedException();
            int incSize = 0;
            int count2 = 0;
            string cipherTxt = "";

            if (plainText.Length % key != 0)  //19 % 2 
            {
                incSize = IncrementUntilDivisible(plainText.Length, key);

            }

            if (incSize == 1)
            {
                int count = 0;
                while (count < key)
                {

                    for (int i = count; i < plainText.Length; i += key) //0 2 4 
                    {

                        cipherTxt += plainText[i];
                    }
                    count++;
                }
                return cipherTxt.ToUpper();
            }
            else if (incSize > 1 || incSize == 0)
            {
                for (int i = 0; i < incSize; i++)
                {
                    plainText += "x";
                }
                while (count2 < key)
                {
                    for (int i = count2; i < plainText.Length; i += key)
                    {
                        cipherTxt += plainText[i];
                    }
                    count2++;
                }
                return cipherTxt.ToUpper();
            }
            return cipherTxt.ToUpper();
        }
    }
}
