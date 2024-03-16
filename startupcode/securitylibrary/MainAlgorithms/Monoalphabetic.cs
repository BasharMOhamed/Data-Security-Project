using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {


            plainText = plainText.Trim().ToLower();
            cipherText = cipherText.Trim().ToLower();

            char[] key = new char[26];

            for (int i = 0; i < plainText.Length; i++)
            {
                //Generate the ASCII code of chars of plainText
                int index = (Convert.ToInt32(plainText[i]) - 97) % 26;
                //Map char value to the right index in key
                key[index] = cipherText[i];
            }
            int ascii_value = 0;

            //Fill the empty indicies in the key array with unique chars
            for (int i = 0; i < 26; i++)
            {
                if (key[i] == '\0')
                {
                    while (key.Contains(Convert.ToChar(ascii_value + 97)))
                    {
                        ascii_value = (ascii_value + 1) % 26;
                    }
                    key[i] = Convert.ToChar(ascii_value + 97);
                }
                ascii_value = (ascii_value + 1) % 26;
            }
            return string.Concat(key).Trim();

        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = " ";

            cipherText = cipherText.Trim().ToLower();
            key = key.Trim().ToLower();

            //Get the ASCII code from the index of chipher char in key array +97
            for (int i = 0; i < cipherText.Length; i++)
            {
                int index = Convert.ToInt32(key.IndexOf(cipherText[i]));
                plainText += Convert.ToChar(index + 97);
            }

            return plainText.Trim();
        }

        public string Encrypt(string plainText, string key)
        {
            string encryptedText = " ";

            plainText = plainText.Trim().ToLower();
            key = key.Trim().ToLower();

            //Get index of key from ASCII code of plaintext char 
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = (Convert.ToInt32(plainText[i]) - 97) % 26;
                encryptedText += key[index];
            }

            return encryptedText.Trim();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {

            cipher = cipher.Trim().ToLower();

            Dictionary<char, long> char_frequency = new Dictionary<char, long>();
            //Calculate the frequency of each char
            for (int i = 0; i < cipher.Length; i++)
            {
                if (char_frequency.ContainsKey(cipher[i]))
                {
                    char_frequency[cipher[i]]++;
                }
                else
                {
                    char_frequency[cipher[i]] = 1;
                }
            }

            //Order the chars by the frequency
            char_frequency = char_frequency.OrderBy(kv => kv.Value).ToDictionary(kv => kv.Key, kv => kv.Value);

            //Frequency table
            char[] frequencyArray = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };


            Dictionary<char, char> key = new Dictionary<char, char>();
            int count = 0;
            //Assign each char according to its frequency to the corresponding char in char table
            for (int i = char_frequency.Count - 1; i >= 0; i--)
            {
                key[char_frequency.ElementAt(i).Key] = frequencyArray[count];
                count++;
            }

            //Extract the plainText
            string plainText = " ";
            for (int i = 0; i < cipher.Length; i++)
            {
                plainText += key[cipher[i]];
            }

            return plainText.Trim();
        }
    }
}
