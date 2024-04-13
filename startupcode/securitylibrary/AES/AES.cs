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

        /*
             02 03 01 01
             01 02 03 01
             01 01 02 03
             03 01 01 02
        */
        string[,] galiosMatrix = { { "02", "03", "01", "01" }, { "01", "02", "03", "01" }, { "01", "01", "02", "03" }, { "03", "01", "01", "02" } };


        /*
                        Rcon
             01 02 04 08 10 20 40 80 1b 36
             00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00   
             00 00 00 00 00 00 00 00 00 00
        */
        string RCon = "01000000020000000400000008000000100000002000000040000000800000001b00000036000000";

        string[] RoundKeys = new string[11];



        //////////////////////// HELPER FUNCTIONS //////////////////////////////////
        
        // Convert From Hexa To Binary
        public static string ToBinary(string hexa)
        {
            string binaryValue = Convert.ToString(Convert.ToInt64(hexa, 16), 2);
            return binaryValue.PadLeft(64, '0');
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

        // Convert With S-BOX
        public string SubBytes(string state, int length)
        {
            string subByteOutput = "";

            for (int i = 0; i < length - 1; i += 2)
            {

                int index1 = Convert.ToInt32(state[i].ToString(), 16);

                int index2 = Convert.ToInt32(state[i + 1].ToString(), 16);

                subByteOutput += sBox[index1, index2];
            }
            return subByteOutput;
        }

        // Shift Rows Function
        public string ShiftLeftRows(string state)
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
                    shiftedRow[col] = stateMatrix[row, (col + row) % 4];
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

        // XOR Between Two Binary variables
        public static string XOR(string binary1, string binary2)
        {
            string result = "";

            for (int i = 0; i < binary1.Length; i++)
            {

                result += binary1[i] == binary2[i] ? '0' : '1';
            }

            return result;
        }


        public string GaliosMultiplictaion(string state, string matrix)
        {

            string binaryState = state;

            string mod = "00011011";

            binaryState += "0";
            binaryState = binaryState.Substring(1);

            switch (matrix)
            {
                case "01":

                    return state;

                case "02":


                    if (state[0] == '1')
                    {

                        return XOR(binaryState, mod);
                    }
                    else
                    {

                        return binaryState;
                    }
                case "03":

                    if (state[0] == '1')
                    {

                        string result = XOR(binaryState, mod);

                        return XOR(result, state);
                    }
                    else
                    {
                        return XOR(binaryState, state);
                    }
            }
            return " ";
        }

        public string MixColumns(string state)
        {
            string mixColumnsOutput = "";

            List<string> galiosResult = new List<string>();



            for (int i = 0; i < 128; i += 32)
            {
                int index;
                for (int j = 0; j < 4; j++)
                {
                    index = i;
                    for (int k = 0; k < 4; k++)
                    {

                        string result = GaliosMultiplictaion(state.Substring(index, 8), galiosMatrix[j, k]);
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

        // Get all Round Keys in array
        void KeyExpansion(string key)
        {
            RoundKeys[0] = key;

            for (int i = 1; i < 11; i++)
            {
                string lastColumn = RoundKeys[i - 1].Substring(96, 32);

                lastColumn = lastColumn.Substring(8) + lastColumn.Substring(0, 8);

                lastColumn = ToBinary(SubBytes(ToHexa(lastColumn).PadLeft(8, '0'), 8));

                string result1 = XOR(lastColumn.Substring(32, 32), RoundKeys[i - 1].Substring(0, 32));

                RoundKeys[i] = XOR(result1, ToBinary(RCon.Substring((i - 1) * 8, 8)).Substring(32, 32));

                for (int j = 0; j < 3; j++)
                {
                    RoundKeys[i] += XOR(RoundKeys[i - 1].Substring((j + 1) * 32 % 128, 32), RoundKeys[i].Substring((j) * 32 % 128, 32));
                }

            }

        }

        // XOR State with Rounded Key
        string AddRoundKey(string plainText, string key)
        {
            return XOR(plainText, key);
        }

        ////////////////////////////////// MAIN FUNCTIONS ///////////////////////////////
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            key = key.Substring(2);
            plainText = plainText.Substring(2);


            string binaryKey1 = ToBinary(key.Substring(0, 16));
            string binaryKey2 = ToBinary(key.Substring(16, 16));
            string binaryKey = binaryKey1 + binaryKey2;


            KeyExpansion(binaryKey);

            string binaryPlainText1 = ToBinary(plainText.Substring(0, 16));
            string binaryPlainText2 = ToBinary(plainText.Substring(16, 16));
            string binaryPlainText = binaryPlainText1 + binaryPlainText2;


            binaryPlainText = AddRoundKey(binaryPlainText, binaryKey);
            for (int i = 0; i < 9; i++)
            {

                string subByteOutput = SubBytes(ToHexa(binaryPlainText), 32);

                string shiftLeftRowsOutput = ShiftLeftRows(subByteOutput);

                string binaryOutput1 = ToBinary(shiftLeftRowsOutput.Substring(0, 16));
                string binaryOutput2 = ToBinary(shiftLeftRowsOutput.Substring(16, 16));
                string binaryOutput = binaryOutput1 + binaryOutput2;

                string mixColumnsOutput = MixColumns(binaryOutput);

                string addRoundKeyOutput = AddRoundKey(mixColumnsOutput, RoundKeys[i + 1]);

                binaryPlainText = addRoundKeyOutput;

            }

            string lastRoundSub = SubBytes(ToHexa(binaryPlainText), 32);
            string lastShiftRow = ShiftLeftRows(lastRoundSub);
            string result1 = ToBinary(lastShiftRow.Substring(0, 16));
            string result2 = ToBinary(lastShiftRow.Substring(16, 16));
            string result = result1 + result2;

            return "0x" + ToHexa(AddRoundKey(result, RoundKeys[10]));
        }
    }
}