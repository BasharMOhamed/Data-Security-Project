using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;


namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    ///



    public class AES : CryptographicTechnique
    {


        string[,] sBox = new string[,]
        {
            {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
            {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
            {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
            {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
            {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
            {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
            {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
            {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
            {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
            {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
            {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
            {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
            {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
            {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
            {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
            {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}
        };

        string[,] INV_SBox = new string[,]
        {
            {"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},
            {"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},
            {"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},
            {"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},
            {"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},
            {"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},
            {"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},
            {"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},
            {"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},
            {"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},
            {"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},
            {"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},
            {"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},
            {"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},
            {"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},
            {"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}
        };

        string[,] INV_galiosMatrix =
        {
            { "0E", "0B", "0D", "09" },
            { "09", "0E", "0B", "0D" },
            { "0D", "09", "0E", "0B" },
            { "0B", "0D", "09", "0E" }
        };

        string[,] galiosMatrix =
        {
            { "02", "03", "01", "01" },
            { "01", "02", "03", "01" },
            { "01", "01", "02", "03" },
            { "03", "01", "01", "02" }
        };

        /*
                        Rcon
             01 02 04 08 10 20 40 80 1b 36
             00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00   
             00 00 00 00 00 00 00 00 00 00
        */
        string RCon = "01000000020000000400000008000000100000002000000040000000800000001b00000036000000";

        string[] RoundKeys = new string[11];

        // Convert From Hexa To Binary
        public static string ToBinary(string hexa)
        {
            string binaryValue1 = Convert.ToString(Convert.ToInt64(hexa.Substring(0, hexa.Length / 2), 16), 2).PadLeft(hexa.Length * 2, '0');
            string binaryValue2 = Convert.ToString(Convert.ToInt64(hexa.Substring(hexa.Length / 2), 16), 2).PadLeft(hexa.Length * 2, '0');
            return binaryValue1 + binaryValue2;
        }

        // Convert From Binary To Hexa
        public static string ToHexa(string binary)
        {
            string hexa = "";
            for (int i = 0; i < binary.Length; i += 4)
            {
                hexa += Convert.ToInt32(binary.Substring(i, 4), 2).ToString("X");
            }

            return hexa;
        }

        // Get The result from (S-Box Matrix / INV S-Box Matrix)      enc: True --> S-Box  False --> INV S-Box
        public string SubBytes(string state, bool enc)
        {
            string subByteOutput = "";

            for (int i = 0; i < state.Length - 1; i += 2)
            {

                int index1 = Convert.ToInt32(state[i].ToString(), 16);

                int index2 = Convert.ToInt32(state[i + 1].ToString(), 16);
                if (enc)
                {
                    subByteOutput += sBox[index1, index2];
                }
                else
                {
                    subByteOutput += INV_SBox[index1, index2];
                }
            }
            return subByteOutput;
        }

        // Shift Rows      enc: True --> Shift The Rows To The Left  False --> Shift The Rows To The Right
        public string ShiftRows(string state, bool enc)
        {
            string[,] stateMatrix = new string[4, 4];
            int stateIndex = 0;
            string shiftedState = "";

            //fill the state matrix
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    stateMatrix[row, col] = state.Substring(stateIndex, 2);
                    stateIndex += 2;
                }
            }

            //shift rows
            for (int row = 1; row < 4; row++)
            {
                string[] shiftedRow = new string[4];
                for (int col = 0; col < 4; col++)
                {
                    if (enc)
                    {
                        shiftedRow[col] = stateMatrix[row, (col + row) % 4];
                    }
                    else
                    {
                        shiftedRow[col] = stateMatrix[row, (col - row + 4) % 4];
                    }
                }

                for (int col = 0; col < 4; col++)
                {
                    stateMatrix[row, col] = shiftedRow[col];
                }
            }

            //convert it back to string
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    shiftedState += stateMatrix[row, col];
                }
            }


            return shiftedState;
        }

        // XOR Between two Binary Variables
        public static string XOR(string binary1, string binary2)
        {
            string result = "";

            for (int i = 0; i < binary1.Length; i++)
            {

                result += binary1[i] == binary2[i] ? '0' : '1';
            }

            return result;
        }

        // GF
        public string GaliosMultiplictaion(string state, string matrix)
        {

            const string IrreduciblePolynomial = "100011011";

            matrix = ToBinary(matrix);

            string result = "00000000";

            while (matrix != "00000000")
            {
                if (matrix[7] == '1')
                {
                    result = XOR(result, state);

                }

                state += '0';

                if (state[0] == '1')
                {

                    state = XOR(IrreduciblePolynomial, state);

                }

                state = state.Substring(1);
                matrix = '0' + matrix.Remove(7);

            }

            return result;

        }

        public string MixColumns(string state, bool enc)
        {
            string mixColumnsOutput = "";

            List<string> galiosResult = new List<string>();
            Console.WriteLine(state.Length);
            string result;
            for (int i = 0; i < 128; i += 32)
            {
                int index;
                for (int j = 0; j < 4; j++)
                {
                    index = i;
                    for (int k = 0; k < 4; k++)
                    {
                        if (enc)
                        {
                            result = GaliosMultiplictaion(state.Substring(index, 8), galiosMatrix[j, k]);
                        }
                        else
                        {
                            result = GaliosMultiplictaion(state.Substring(index, 8), INV_galiosMatrix[j, k]);
                        }
                        galiosResult.Add(result);
                        index += 8;
                    }
                }


            }

            for (int i = 0; i < galiosResult.Count; i += 4)
            {

                string result1 = XOR(galiosResult[i], galiosResult[i + 1]);

                string result2 = XOR(galiosResult[i + 2], galiosResult[i + 3]);

                mixColumnsOutput += XOR(result1, result2);

            }

            return mixColumnsOutput;
        }

        // Store The 11 Keys in Array
        void KeyExpansion(string key)
        {
            RoundKeys[0] = key;

            for (int i = 1; i < 11; i++)
            {
                string lastColumn = RoundKeys[i - 1].Substring(96, 32);

                lastColumn = lastColumn.Substring(8) + lastColumn.Substring(0, 8);

                lastColumn = ToBinary(SubBytes(ToHexa(lastColumn).PadLeft(8, '0'), true));

                string result1 = XOR(lastColumn, RoundKeys[i - 1].Substring(0, 32));

                RoundKeys[i] = XOR(result1, ToBinary(RCon.Substring((i - 1) * 8, 8)));

                for (int j = 0; j < 3; j++)
                {
                    RoundKeys[i] += XOR(RoundKeys[i - 1].Substring((j + 1) * 32 % 128, 32), RoundKeys[i].Substring((j) * 32 % 128, 32));
                }

            }

        }

        string AddRoundKey(string plainText, string key)
        {
            return XOR(plainText, key);
        }

        public override string Decrypt(string cipherText, string key)
        {

            key = key.Substring(2);
            cipherText = cipherText.Substring(2);
            string binaryKey = ToBinary(key);

            KeyExpansion(binaryKey);

            string binaryCipherText = ToBinary(cipherText);

            binaryCipherText = AddRoundKey(binaryCipherText, RoundKeys[10]);

            for (int i = 9; i > 0; i--)
            {
                string InvShiftRows = ShiftRows(ToHexa(binaryCipherText), false);
                string InvsubBytes = SubBytes(InvShiftRows, false);

                string binaryOutput = ToBinary(InvsubBytes);

                string InvAddRoundKey = AddRoundKey(binaryOutput, RoundKeys[i]);
                binaryCipherText = MixColumns(InvAddRoundKey, false);
            }

            string LastInvShiftRows = ShiftRows(ToHexa(binaryCipherText), false);
            string LastInvsubBytes = SubBytes(LastInvShiftRows, false);

            string binarySubBytes = ToBinary(LastInvsubBytes);

            string LastInvAddRoundKey = AddRoundKey(binarySubBytes, RoundKeys[0]);

            return "0x" + ToHexa(LastInvAddRoundKey);
        }

        public override string Encrypt(string plainText, string key)
        {
            key = key.Substring(2);
            plainText = plainText.Substring(2);

            string binaryKey = ToBinary(key);


            KeyExpansion(binaryKey);

            string binaryPlainText = ToBinary(plainText);


            binaryPlainText = AddRoundKey(binaryPlainText, binaryKey);
            for (int i = 0; i < 9; i++)
            {

                string subByteOutput = SubBytes(ToHexa(binaryPlainText), true);

                string shiftLeftRowsOutput = ShiftRows(subByteOutput, true);

                string binaryOutput = ToBinary(shiftLeftRowsOutput);

                string mixColumnsOutput = MixColumns(binaryOutput, true);

                string addRoundKeyOutput = AddRoundKey(mixColumnsOutput, RoundKeys[i + 1]);

                binaryPlainText = addRoundKeyOutput;

            }

            string lastRoundSub = SubBytes(ToHexa(binaryPlainText), true);
            string lastShiftRow = ShiftRows(lastRoundSub, true);
            string result = ToBinary(lastShiftRow);

            return "0x" + ToHexa(AddRoundKey(result, RoundKeys[10]));
        }
    }
}