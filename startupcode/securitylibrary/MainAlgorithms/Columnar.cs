using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();


            // calculating the count of cols and rows
            int firstIndex = 0, secondIndex = 0, plainIndex = 0;
            string modifiedPlainText = "";
            firstIndex = plainText.IndexOf(cipherText[0].ToString().ToLower());
            secondIndex = plainText.IndexOf(cipherText[1].ToString().ToLower());
            if (firstIndex == secondIndex)
            {
                if (plainText[firstIndex] == plainText[firstIndex + 1])
                {
                    modifiedPlainText = plainText.Remove(firstIndex, 1);
                    firstIndex = modifiedPlainText.IndexOf(cipherText[0].ToString().ToLower()) + 1;
                    modifiedPlainText = plainText.Remove(firstIndex - 1, 2);
                    secondIndex = modifiedPlainText.IndexOf(cipherText[1].ToString().ToLower()) + 2;
                }
                else
                {
                    modifiedPlainText = plainText.Remove(firstIndex, 1);
                    secondIndex = modifiedPlainText.IndexOf(cipherText[1].ToString().ToLower()) + 1;
                }
            }
            int colsNum = Math.Abs(firstIndex - secondIndex);
            List<int> key = new List<int>(colsNum);
            int rowsNum = (int)Math.Ceiling((double)cipherText.Length / colsNum);
            char[,] matrix = new char[rowsNum, colsNum];


            //fill the matrix
            for (int i = 0; i < rowsNum; i++)
            {
                for (int j = 0; j < colsNum; j++)
                {
                    if (plainIndex < plainText.Length)
                    {
                        matrix[i, j] = plainText[plainIndex];
                        plainIndex++;
                    }
                    else
                    {
                        matrix[i, j] = 'X';

                    }
                }
            }


            //split the ciphertext to substrings
            List<string> substrings = new List<string>();
            int substringLength = rowsNum;
            for (int i = 0; i < cipherText.Length; i += substringLength)
            {
                int remainingLength = Math.Min(substringLength, cipherText.Length - i);
                string substring = cipherText.Substring(i, remainingLength).ToLower();
                substrings.Add(substring);
            }


            //find the order of the key by comparing the substrings with the columns
            for (int i = 0; i < colsNum; i++)
            {
                string temp = "";
                for (int j = 0; j < rowsNum; j++)
                {
                    temp += matrix[j, i];
                }
                int colOrder = substrings.FindIndex((str) => str.Equals(temp)) + 1;
                key.Add(colOrder);
            }


            return key;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();

            string plainText = "";
            int cipherIndex = 0;
            int rowsNum = (int)Math.Ceiling((double)cipherText.Length / key.Count);
            char[,] decryptedMatrix = new char[rowsNum, key.Count];

            //fill the matrix with the columns order of the key 
            for (int i = 0; i < key.Count; i++)
            {
                int colIndex = key.FindIndex((num) => num == i + 1);
                for (int j = 0; j < rowsNum; j++)
                {
                    if (cipherIndex < cipherText.Length)
                    {
                        decryptedMatrix[j, colIndex] = cipherText[cipherIndex];
                        cipherIndex++;
                    }
                    else
                    {
                        decryptedMatrix[j, colIndex] = 'X';
                    }
                }
            }
            //read out the matrix row wise
            for (int i = 0; i < rowsNum; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    plainText += decryptedMatrix[i, j].ToString().ToLower();
                }
            }


            return plainText;
        }



        public string Encrypt(string plainText, List<int> key)
        {
            // throw new NotImplementedException();

            plainText = plainText.Replace(" ", "").ToUpper();
            string cipherText = "";
            int plainIndex = 0;
            int rowsNum = (int)Math.Ceiling((double)plainText.Length / key.Count);
            char[,] encryptedMatrix = new char[rowsNum, key.Count];


            //fill the matrix
            for (int i = 0; i < rowsNum; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (plainIndex < plainText.Length)
                    {
                        encryptedMatrix[i, j] = plainText[plainIndex];
                        plainIndex++;
                    }
                    else
                    {
                        encryptedMatrix[i, j] = 'X';

                    }
                }
            }
            //read out the matrix with the order of the key
            for (int i = 0; i < key.Count; i++)
            {
                int colIndex = key.FindIndex((num) => num == i + 1);
                for (int j = 0; j < rowsNum; j++)
                {
                    cipherText += encryptedMatrix[j, colIndex];
                }
            }


            return cipherText;

        }
    }
}
