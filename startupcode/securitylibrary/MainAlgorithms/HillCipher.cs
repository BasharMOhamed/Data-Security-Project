using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new InvalidAnlysisException();
        }
        /*
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }*/

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainTextList = new List<int>();
            int m = (int)Math.Sqrt(key.Count);
            int[,] keyMatrix = new int[m, m];

            int count = 0;
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    keyMatrix[i, j] = key[count];
                    count++;
                }
            }

            if (m == 2)
            {
                int det = (keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[0, 1] * keyMatrix[1, 0]) + 26000;


                bool found = false;
                //Find mod of multiplicative inverse
                for (int i = 0; i < 26; i++)
                {
                    if (det * i % 26 == 1)
                    {
                        det = i;
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    throw new Exception();
                }

                int temp = keyMatrix[0, 0];
                keyMatrix[0, 0] = (det * keyMatrix[1, 1]) % 26;
                keyMatrix[1, 1] = (det * temp) % 26;
                keyMatrix[0, 1] = (keyMatrix[0, 1] * det * -1) % 26;
                keyMatrix[1, 0] = keyMatrix[1, 0] * (det * -1) % 26;


                //Remove any -ve number 
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        if (keyMatrix[i, j] < 0)
                        {
                            keyMatrix[i, j] += 26;
                        }
                    }
                }


                int result = 0;
                for (int i = 0; i < cipherText.Count; i += 2)
                {

                    List<int> cipherTextList = new List<int>();
                    //Add each 2 numbers into a list
                    for (int j = 0; j < m; j++)
                    {
                        cipherTextList.Add(cipherText[i + j]);

                    }

                    //Multiply k with c
                    for (int j = 0; j < m; j++)
                    {
                        result = 0;
                        for (int k = 0; k < m; k++)
                        {
                            result += keyMatrix[j, k] * cipherTextList[k];
                        }

                        plainTextList.Add(result % 26);
                    }
                }


            }
            else if (m == 3)
            {
                int[] determants = new int[9];
                determants[0] = ((keyMatrix[1, 1] * keyMatrix[2, 2]) - (keyMatrix[2, 1] * keyMatrix[1, 2]));
                determants[1] = ((keyMatrix[1, 0] * keyMatrix[2, 2]) - (keyMatrix[1, 2] * keyMatrix[2, 0]));
                determants[2] = ((keyMatrix[1, 0] * keyMatrix[2, 1]) - (keyMatrix[1, 1] * keyMatrix[2, 0]));

                int resultDet = ((keyMatrix[0, 0] * determants[0] - keyMatrix[0, 1] * determants[1] + keyMatrix[0, 2] * determants[2]) + 26000) % 26;

                bool found = false;
                //Find mod of multiplicative inverse
                for (int i = 0; i < 26; i++)
                {
                    if (resultDet * i % 26 == 1)
                    {
                        resultDet = i;
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    throw new Exception();
                }

                determants[3] = ((keyMatrix[0, 1] * keyMatrix[2, 2]) - (keyMatrix[2, 1] * keyMatrix[0, 2]));
                determants[4] = ((keyMatrix[0, 0] * keyMatrix[2, 2]) - (keyMatrix[0, 2] * keyMatrix[2, 0]));
                determants[5] = ((keyMatrix[0, 0] * keyMatrix[2, 1]) - (keyMatrix[0, 1] * keyMatrix[2, 0]));
                determants[6] = ((keyMatrix[0, 1] * keyMatrix[1, 2]) - (keyMatrix[0, 2] * keyMatrix[1, 1]));
                determants[7] = ((keyMatrix[0, 0] * keyMatrix[1, 2]) - (keyMatrix[0, 2] * keyMatrix[1, 0]));
                determants[8] = ((keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[0, 1] * keyMatrix[1, 0]));

                List<int> keyList = new List<int>() { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                int index = 0;
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        int keyResult = ((resultDet * (int)Math.Pow((double)-1, (double)index)) * determants[index]) + 26000;
                        index++;
                        keyList.RemoveAt((m * j) + i);
                        keyList.Insert((m * j) + i, keyResult % 26);
                    }
                }



                plainTextList = Encrypt(cipherText, keyList);

            }

            return plainTextList;
        }

        public string Decrypt(string cipherText, string key)
        {

            string plainText = "";
            key = key.ToLower();
            cipherText = cipherText.ToLower();

            List<int> keyList = new List<int>();
            List<int> cipherTextList = new List<int>();

            for (int i = 0; i < key.Length; i++)
            {
                keyList.Add((((int)key[i]) - 97) % 26);
            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                cipherTextList.Add((((int)cipherText[i]) - 97) % 26);
            }

            List<int> plainTextList = Decrypt(cipherTextList, keyList);

            for (int i = 0; i < plainTextList.Count; i++)
            {

                plainText += Convert.ToChar(plainTextList[i] + 97);
            }

            return plainText;

        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {

            List<int> cipherList = new List<int>();
            int m = (int)Math.Sqrt(key.Count);
            int[,] keyMatrix = new int[m, m];

            int count = 0;
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    keyMatrix[i, j] = key[count];
                    count++;
                }
            }

            int result = 0;
            for (int i = 0; i < plainText.Count; i += m)
            {
                result = 0;
                List<int> plainTextList = new List<int>();

                for (int j = 0; j < m; j++)
                {
                    plainTextList.Add(plainText[i + j]);

                }

                for (int j = 0; j < m; j++)
                {
                    result = 0;
                    for (int k = 0; k < m; k++)
                    {
                        result += keyMatrix[j, k] * plainTextList[k];
                    }
                    cipherList.Add(result % 26);
                }

            }

            return cipherList;

        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            key = key.ToLower();
            plainText = plainText.ToLower();

            List<int> keyList = new List<int>();
            List<int> plainTextList = new List<int>();

            for (int i = 0; i < key.Length; i++)
            {
                keyList.Add((((int)key[i]) - 97) % 26);
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                plainTextList.Add((((int)plainText[i]) - 97) % 26);
            }

            List<int> cipherTextList = Encrypt(plainTextList, keyList);

            for (int i = 0; i < cipherTextList.Count; i++)
            {

                cipherText += Convert.ToChar(cipherTextList[i] + 97);
            }

            return cipherText;
        }
    }
}
