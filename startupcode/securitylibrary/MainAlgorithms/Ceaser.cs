using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        string alphabet = "abcdefghijklmnopqrstuvwxyz";
        public string Encrypt(string plainText, int key)
        {
            // throw new NotImplementedException();


            string cipherText = "";
            plainText = plainText.ToLower();
            int res;
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {

                    if (plainText[i] == alphabet[j])
                    {

                        res = (j + key) % 26;
                        cipherText += alphabet[res];
                    }

                }

            }
            return cipherText.ToUpper();
        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();

            cipherText = cipherText.ToLower();
            string orgText = "";
            int res;
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {

                    if (cipherText[i] == alphabet[j])
                    {

                        res = (j - key) % 26;
                        if (res < 0)
                        {
                            res *= -1;
                            res = 26 - res;

                        }
                        orgText += alphabet[res];
                    }

                }

            }
            return orgText.ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char firstCharOfPt = plainText[0];
            int indexOfPT = alphabet.IndexOf(firstCharOfPt);
            char firstCharOfCt = cipherText[0];
            int indexOfCt = alphabet.IndexOf(firstCharOfCt);
            int key = (indexOfCt - indexOfPT) % 26;
            if (key < 0)
            {
                key *= -1;
                key = 26 - key;
            }

            return key;
        }
    }
}
