using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES algo = new DES();
        public string Decrypt(string cipherText, List<string> key)
        {
            return algo.Decrypt(algo.Encrypt(algo.Decrypt(cipherText, key[0]), key[1]), key[0]);
        }

        public string Encrypt(string plainText, List<string> key)
        {
            return algo.Encrypt(algo.Decrypt(algo.Encrypt(plainText, key[0]), key[1]), key[0]);
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
