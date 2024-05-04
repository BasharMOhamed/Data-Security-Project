using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            /*throw new NotImplementedException();*/
            return Encrypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            bool hexa = false;
            if(plainText[0] == '0' && plainText[1] == 'x')
            {
                hexa = true;
                plainText = HexaToString(plainText);
                key = HexaToString(key);
            }
            List<int> S = new List<int>();
            List<int> T = new List<int>();
            string cipher = "";

            for(int i = 0; i < 256; i++)
            {
                S.Add(i);
                T.Add((key[i % key.Length]) - 0);
            }

            int j = 0, temp;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                // swap
                temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            int x = 0,y = 0, k;
            for (int l = 0; l < plainText.Length; l++) 
            { 
                x = (x + 1) % 256;
                y = (y + S[x]) % 256;
                // swap
                temp = S[x];
                S[x] = S[y];
                S[y] = temp;

                k = S[(S[x] + S[y]) % 256];
                cipher +=(char)(plainText[l] ^ k);
            }

            if (hexa)
            {
                cipher = StringToHexa(cipher);
            }



            return cipher;
        }
        public static string HexaToString(string hexa)
        {
            string result = "";
            for (int i = 2; i < hexa.Length; i += 2)
            {
                string hexChar = hexa.Substring(i, 2);
                byte byteValue = Convert.ToByte(hexChar, 16);
                result += (char)byteValue;
            }
            return result;
        }
        public static string StringToHexa(string String)
        {
            string result = "0x";
            for(int i = 0; i < String.Length; i++)
            {
                result += ((int)String[i]).ToString("X2");
            }
            return result;
        }
    }
}
