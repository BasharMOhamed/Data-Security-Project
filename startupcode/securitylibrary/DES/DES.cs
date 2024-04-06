﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>

    public class DES : CryptographicTechnique
    {
        public static List<List<int>> Boxes = new List<List<int>>();
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            /*throw new NotImplementedException();*/
            // The 8 S-Boxes
            Boxes.Add(new List<int> { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 });
            Boxes.Add(new List<int> { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 });
            Boxes.Add(new List<int> { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 });
            Boxes.Add(new List<int> { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 });
            Boxes.Add(new List<int> { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 });
            Boxes.Add(new List<int> { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 });
            Boxes.Add(new List<int> { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 });
            Boxes.Add(new List<int> { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 });

            // All Permuations
            List<int> PC1 = new List<int>() { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
            List<int> PC2 = new List<int>() { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
            List<int> IP = new List<int>() { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
            List<int> EBIT = new List<int>() { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
            List<int> P = new List<int> { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
            List<int> P_1 = new List<int> { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
            string Permutated, C, D, L, R, temp;



            // Convert The key And The Message From Hexa to Binary
            string M = plainText;
            M = ToBinary(M);
            key = ToBinary(key);

            // Permutate The key And create The C0 And D0
            key = Permutate(key, PC1);
            C = key.Substring(0, 28);
            D = key.Substring(28);

            // Permutate The Message And Create The L0 And R0
            M = Permutate(M, IP);
            L = M.Substring(0, 32);
            R = M.Substring(32);
            for (int i = 0; i < 16; i++)
            {
                temp = R;
                // Make The R -> 48 bit
                R = Permutate(R, EBIT);
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    C = ShiftLeft(C, 1);
                    D = ShiftLeft(D, 1);

                }
                else
                {
                    C = ShiftLeft(C, 2);
                    D = ShiftLeft(D, 2);
                }
                key = C + D;
                // key(i + 1) after Permutation with P-2
                Permutated = Permutate(key, PC2);

                R = XOR(R, Permutated);
                // Make The R -> 32 Bit With S-Boxes
                R = GetSBoxOutput(R);

                // Final Permutation
                R = Permutate(R, P);
                R = XOR(R, L);
                L = temp;

            }
            string Cipher = Permutate(R + L, P_1);
            Cipher = ToHexa(Cipher);
            return "0x" + Cipher;
        }
        public static string GetSBoxOutput(string input)
        {
            String result = "";
            for (int i = 0; i < input.Length; i += 6)
            {
                string group = input.Substring(i, 6);
                // Concatinate The First bit and the last bit to get the row in S-Box
                int row = Convert.ToInt32(group[0].ToString() + group[5].ToString(), 2);
                // Others are the column
                int col = Convert.ToInt32(group.Substring(1, 4), 2);
                int sBoxIndex = i / 6;
                int sBoxValue = Boxes[sBoxIndex][row * 16 + col];
                result += Convert.ToString(sBoxValue, 2).PadLeft(4, '0');
            }
            return result.ToString();
        }

        public static string XOR(string binary1, string binary2)
        {
            string result = "";
            for (int i = 0; i < binary1.Length; i++)
            {
                result += binary1[i] == binary2[i] ? '0' : '1';
            }

            return result;
        }
        public static string Permutate(string value, List<int> PC)
        {
            string PermutatedValue = "";
            for (int i = 0; i < PC.Count; i++)
            {
                PermutatedValue += value[PC.ElementAt(i) - 1];
            }
            return PermutatedValue;
        }
        public static string ToBinary(string hexa)
        {
            string binaryValue = Convert.ToString(Convert.ToInt64(hexa, 16), 2);
            return binaryValue.PadLeft(64, '0');
        }
        public static string ToHexa(string binary)
        {
            string hexa = "";
            for (int i = 0; i < binary.Length; i += 4)
            {
                hexa += Convert.ToInt32(binary.Substring(i, 4), 2).ToString("X");
            }
            return hexa;
        }
        public static string ShiftLeft(string binary, int amount)
        {
            return binary.Substring(amount) + binary.Substring(0, amount);
        }
    }
}
