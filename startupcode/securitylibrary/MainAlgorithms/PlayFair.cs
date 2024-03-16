using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            Dictionary<char, int> keyDictionary = new Dictionary<char, int>();

            int count = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (!keyDictionary.ContainsKey(key[i]))
                {
                    keyDictionary[key[i]] = count;
                    count++;
                }
            }

            int index = keyDictionary.Count;
            for (int i = 0; i < 26; i++)
            {
                if (Convert.ToChar(i + 97) == 'j')
                {
                    continue;
                }
                if (!keyDictionary.ContainsKey(Convert.ToChar(i + 97)))
                {
                    keyDictionary[Convert.ToChar(i + 97)] = index;
                    index++;
                }
            }

            for (int i = 0; i < cipherText.Length - 1; i += 2)
            {
                int row1 = 0, row2 = 0, col1 = 0, col2 = 0;

                row1 = keyDictionary[cipherText[i]] / 5;
                col1 = keyDictionary[cipherText[i]] % 5;
                row2 = keyDictionary[cipherText[i + 1]] / 5;
                col2 = keyDictionary[cipherText[i + 1]] % 5;


                if (row1 == row2)
                {
                    int new_col1 = ((col1 - 1) + 5) % 5;
                    plainText += keyDictionary.ElementAt((row1 * 5) + new_col1).Key;
                    int new_col2 = ((col2 - 1) + 5) % 5;
                    plainText += keyDictionary.ElementAt((row2 * 5) + new_col2).Key;
                }
                else if (col1 == col2)
                {
                    int new_row1 = ((row1 - 1) + 5) % 5;
                    plainText += keyDictionary.ElementAt((new_row1 * 5) + col1).Key;
                    int new_row2 = ((row2 - 1) + 5) % 5;
                    plainText += keyDictionary.ElementAt((new_row2 * 5) + col2).Key;
                }
                else
                {
                    plainText += keyDictionary.ElementAt((row1 * 5) + col2).Key;
                    plainText += keyDictionary.ElementAt((row2 * 5) + col1).Key;
                }

            }


            for (int i = 1; i < plainText.Length; i += 2)
            {
                if (plainText[i] == 'x' && i == plainText.Length - 1)
                {
                    plainText = plainText.Remove(i, 1);
                    break;
                }

                if (plainText[i].Equals('x'))
                {
                    if (plainText[i - 1].Equals(plainText[i + 1]))
                    {
                        plainText = plainText.Remove(i, 1);
                        i--;
                    }
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            Dictionary<char, int> keyDictionary = new Dictionary<char, int>();

            int count = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (!keyDictionary.ContainsKey(key[i]))
                {
                    keyDictionary[key[i]] = count;
                    count++;
                }
            }

            int index = keyDictionary.Count;
            for (int i = 0; i < 26; i++)
            {
                if (Convert.ToChar(i + 97) == 'j')
                {
                    continue;
                }
                if (!keyDictionary.ContainsKey(Convert.ToChar(i + 97)))
                {
                    keyDictionary[Convert.ToChar(i + 97)] = index;
                    index++;
                }
            }

            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
            }
            if (plainText.Length % 2 != 0)
            {
                plainText += "x";
            }

            for (int i = 0; i < plainText.Length - 1; i += 2)
            {

                int row1 = keyDictionary[plainText[i]] / 5;
                int col1 = keyDictionary[plainText[i]] % 5;
                int row2 = keyDictionary[plainText[i + 1]] / 5;
                int col2 = keyDictionary[plainText[i + 1]] % 5;

                if (row1 == row2)
                {
                    int new_col1 = (col1 + 1) % 5;
                    cipherText += keyDictionary.ElementAt((row1 * 5) + new_col1).Key;
                    int new_col2 = (col2 + 1) % 5;
                    cipherText += keyDictionary.ElementAt((row2 * 5) + new_col2).Key;

                }
                else if (col1 == col2)
                {
                    int new_row1 = (row1 + 1) % 5;
                    cipherText += keyDictionary.ElementAt((new_row1 * 5) + col1).Key;
                    int new_row2 = (row2 + 1) % 5;
                    cipherText += keyDictionary.ElementAt((new_row2 * 5) + col2).Key;
                }
                else
                {
                    cipherText += keyDictionary.ElementAt((row1 * 5) + col2).Key;
                    cipherText += keyDictionary.ElementAt((row2 * 5) + col1).Key;
                }
            }

            return cipherText.ToUpper();

        }
    }
}
