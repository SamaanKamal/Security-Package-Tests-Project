using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public static string[,] SBOX = new string[16, 16]
        {
            { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
            { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
            { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
            { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
            { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
            { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
            { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
            { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
            { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
            { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
            { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
            { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
            { "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
            { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
            { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
            { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" }
        };
        public static string[,] InverseSBOX = new string[16, 16]
        {
                { "0x52", "0x09", "0x6a", "0xd5", "0x30", "0x36", "0xa5", "0x38", "0xbf", "0x40", "0xa3", "0x9e", "0x81", "0xf3", "0xd7", "0xfb" },
                { "0x7c", "0xe3", "0x39", "0x82", "0x9b", "0x2f", "0xff", "0x87", "0x34", "0x8e", "0x43", "0x44", "0xc4", "0xde", "0xe9", "0xcb" },
                { "0x54", "0x7b", "0x94", "0x32", "0xa6", "0xc2", "0x23", "0x3d", "0xee", "0x4c", "0x95", "0x0b", "0x42", "0xfa", "0xc3", "0x4e" },
                { "0x08", "0x2e", "0xa1", "0x66", "0x28", "0xd9", "0x24", "0xb2", "0x76", "0x5b", "0xa2", "0x49", "0x6d", "0x8b", "0xd1", "0x25" },
                { "0x72", "0xf8", "0xf6", "0x64", "0x86", "0x68", "0x98", "0x16", "0xd4", "0xa4", "0x5c", "0xcc", "0x5d", "0x65", "0xb6", "0x92" },
                { "0x6c", "0x70", "0x48", "0x50", "0xfd", "0xed", "0xb9", "0xda", "0x5e", "0x15", "0x46", "0x57", "0xa7", "0x8d", "0x9d", "0x84" },
                { "0x90", "0xd8", "0xab", "0x00", "0x8c", "0xbc", "0xd3", "0x0a", "0xf7", "0xe4", "0x58", "0x05", "0xb8", "0xb3", "0x45", "0x06" },
                { "0xd0", "0x2c", "0x1e", "0x8f", "0xca", "0x3f", "0x0f", "0x02", "0xc1", "0xaf", "0xbd", "0x03", "0x01", "0x13", "0x8a", "0x6b" },
                { "0x3a", "0x91", "0x11", "0x41", "0x4f", "0x67", "0xdc", "0xea", "0x97", "0xf2", "0xcf", "0xce", "0xf0", "0xb4", "0xe6", "0x73" },
                { "0x96", "0xac", "0x74", "0x22", "0xe7", "0xad", "0x35", "0x85", "0xe2", "0xf9", "0x37", "0xe8", "0x1c", "0x75", "0xdf", "0x6e" },
                { "0x47", "0xf1", "0x1a", "0x71", "0x1d", "0x29", "0xc5", "0x89", "0x6f", "0xb7", "0x62", "0x0e", "0xaa", "0x18", "0xbe", "0x1b" },
                { "0xfc", "0x56", "0x3e", "0x4b", "0xc6", "0xd2", "0x79", "0x20", "0x9a", "0xdb", "0xc0", "0xfe", "0x78", "0xcd", "0x5a", "0xf4" },
                { "0x1f", "0xdd", "0xa8", "0x33", "0x88", "0x07", "0xc7", "0x31", "0xb1", "0x12", "0x10", "0x59", "0x27", "0x80", "0xec", "0x5f" },
                { "0x60", "0x51", "0x7f", "0xa9", "0x19", "0xb5", "0x4a", "0x0d", "0x2d", "0xe5", "0x7a", "0x9f", "0x93", "0xc9", "0x9c", "0xef" },
                { "0xa0", "0xe0", "0x3b", "0x4d", "0xae", "0x2a", "0xf5", "0xb0", "0xc8", "0xeb", "0xbb", "0x3c", "0x83", "0x53", "0x99", "0x61" },
                { "0x17", "0x2b", "0x04", "0x7e", "0xba", "0x77", "0xd6", "0x26", "0xe1", "0x69", "0x14", "0x63", "0x55", "0x21", "0x0c", "0x7d" }
        };

        public static string[,] gf = new string[4, 4]
        {
            {"0E","0B","0D","09"},
            {"09","0E","0B","0D"},
            {"0D","09","0E","0B"},
            {"0B","0D","09","0E"}

        };

        public static string[,] RCON = new string[4, 10] {
            {"01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" } ,
            {"00","00","00","00","00","00","00","00","00","00", },
            {"00","00","00","00","00","00","00","00","00","00", },
            {"00","00","00","00","00","00","00","00","00","00", }
        };
        public static string[,] InverseSubBytes(string[,] matrix)
        {
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string temp1 = (matrix[i, j][0]).ToString();
                    string temp2 = (matrix[i, j][1]).ToString();
                    int value1 = Convert.ToInt32(temp1, 16);
                    int value2 = Convert.ToInt32(temp2, 16);
                    result[i, j] = InverseSBOX[value1, value2];
                }
            }

            return result;
        }

        public static string[,] InverseShiftRows(string[,] matrix)
        {
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = matrix[i, j];
                    if (i == 1)
                    {
                        result[i, j] = matrix[i, ((j - 1) + 4) % 4];
                    }

                    if (i == 2)
                    {
                        result[i, j] = matrix[i, ((j - 2) + 4) % 4];
                    }

                    if (i == 3)
                    {
                        result[i, j] = matrix[i, ((j - 3) + 4) % 4];
                    }
                }
            }
            return result;
        }
        public static string ShiftString(string t)
        {
            return t.Substring(1, t.Length - 1) + '0';
        }


        public static string xor(string index)
        {
            string result = "";
            string one_B = "00011011";
            for (int i = 0; i < index.Length; i++)
            {
                if (index[i] == one_B[i])
                    result += "0";
                else
                    result += "1";
            }
            return result;
        }
        public static string GF2(string index)
        {
            string binary = toBinary(index);
            string tempResult = "";
            if (binary[0].ToString() == "1")
            {
                tempResult = ShiftString(binary);
                tempResult = xor(tempResult);
            }
            else if (binary[0].ToString() == "0")
            {
                tempResult = ShiftString(binary);
            }
            string result = BinaryStringToHexString(tempResult);
            string Finalresult = result;
            return Finalresult;
        }
        public static string[,] InverseMixColumns(string[,] matrix)
        {
            string[,] result = new string[4, 4];
            int res = 0;
            int temp1 = 0;
            int temp2 = 0;
            int val1 = 0;
            int val2 = 0;
            int val3 = 0;
            int val4 = 0;
            int count = 0;
            int row = 0;
            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    int coloumn = 0;
                    for (int l = 0; l < 4; l++)
                    {
                        if (coloumn % 4 == 0)
                        {
                            coloumn = 0;
                        }
                        if (gf[row, coloumn] == "09")
                        {
                            temp1 = Convert.ToInt32(GF2(GF2(GF2(matrix[l, k]))), 16);
                            temp2 = Convert.ToInt32(matrix[l, k], 16);
                            res = temp1 ^ temp2;
                            val1 = res;

                        }
                        else if (gf[row, coloumn] == "0B")
                        {
                            temp1 = Convert.ToInt32(GF2(GF2(matrix[l, k])), 16);
                            temp2 = Convert.ToInt32(matrix[l, k], 16);
                            int temp3 = temp1 ^ temp2;
                            string t = Convert.ToString(temp3, 16);
                            int temp4 = Convert.ToInt32(GF2(t), 16);
                            res = temp4 ^ temp2;
                            val2 = res;

                        }
                        else if (gf[row, coloumn] == "0D")
                        {
                            res = 0;
                            temp1 = Convert.ToInt32(GF2(matrix[l, k]), 16);
                            temp2 = Convert.ToInt32(matrix[l, k], 16);
                            int temp3 = temp1 ^ temp2;
                            string t = Convert.ToString(temp3, 16);
                            int temp4 = Convert.ToInt32(GF2(GF2((t))), 16);
                            res = temp4 ^ temp2;
                            val3 = res;

                        }
                        else if (gf[row, coloumn] == "0E")
                        {
                            temp1 = Convert.ToInt32(GF2(matrix[l, k]), 16);
                            temp2 = Convert.ToInt32(matrix[l, k], 16);
                            int temp3 = temp1 ^ temp2;
                            string t = Convert.ToString(temp3, 16);
                            int temp4 = Convert.ToInt32(GF2(t), 16);
                            int temp5 = temp4 ^ temp2;
                            string tt = Convert.ToString(temp5, 16);
                            res = Convert.ToInt32(GF2(tt), 16);
                            val4 = res;

                        }
                        coloumn++;

                    }

                    int finalResult = val1 ^ val3 ^ val2 ^ val4;
                    result[row, count] = Convert.ToString(finalResult, 16);
                    if (result[row, count].Length == 1)
                    {
                        result[row, count] = "0" + Convert.ToString(finalResult, 16);
                    }
                    count++;
                    if (count % 4 == 0)
                    {
                        count = 0;
                    }
                }
                row++;
            }
            return result;
        }

        public string[,] AddRoundKey(string[,] matrix, string[,] Key)
        {
            int[,] TempMatrix1 = new int[4, 4];
            int[,] TempMatrix2 = new int[4, 4];
            int[,] TempResult = new int[4, 4];
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    TempMatrix1[i, j] = Convert.ToInt32(matrix[i, j], 16);
                    TempMatrix2[i, j] = Convert.ToInt32(Key[i, j], 16);
                    TempResult[i, j] = TempMatrix1[i, j] ^ TempMatrix2[i, j];
                    result[i, j] = Convert.ToString(TempResult[i, j], 16);
                    if (result[i, j].Length == 1)
                    {
                        result[i, j] = "0" + Convert.ToString((TempMatrix1[i, j] ^ TempMatrix2[i, j]), 16);
                    }
                }
            }
            return result;
        }
        public static string toBinary(string index)
        {
            index = Convert.ToString(Convert.ToInt32(index, 16), 2);
            if (index.Length < 8)
            {
                index = (new String('0', 8 - index.Length) + index);
            }
            return index;
        }

        public static string BinaryStringToHexString(string binary)
        {
            if (string.IsNullOrEmpty(binary))
                return binary;

            StringBuilder result = new StringBuilder(binary.Length / 8 + 1);

            // TODO: check all 1's or 0's... throw otherwise

            int mod4Len = binary.Length % 8;
            if (mod4Len != 0)
            {
                // pad to length multiple of 8
                binary = binary.PadLeft(((binary.Length / 8) + 1) * 8, '0');
            }

            for (int i = 0; i < binary.Length; i += 8)
            {
                string eightBits = binary.Substring(i, 8);
                result.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
            }

            return result.ToString();
        }

        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            string[,] cipherMatrix = new string[4, 4];
            string[,] keyMatrix = new string[4, 4];
            int countKey = 0;
            int countCipher = 0;
            int round = 0;
            cipherText = cipherText.Remove(0, 2);
            key = key.Remove(0, 2);
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    cipherMatrix[i, j] = cipherText[countCipher++].ToString() + cipherText[countCipher++].ToString();
                    keyMatrix[i, j] = key[countKey++].ToString() + key[countKey++].ToString();

                }
            }
            // first round ///
            List<string[,]> result = new List<string[,]>();
            result.Add(keyMatrix);
            int count = 0;
            int KeyRound = 0;
            int[,] TempMatrix1 = new int[4, 4];
            int[,] TempMatrix2 = new int[4, 4];
            int[,] TempResult = new int[4, 4];
            int[,] intRcon = new int[4, 10];
            for (int j = 0; j < 10; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    intRcon[i, j] = Convert.ToInt32(RCON[i, j], 16);
                }
            }
            while (KeyRound < 10)
            {
                string[,] Temp = keyMatrix;
                keyMatrix = new string[4, 4];
                for (int j = 0; j < 4; j++)
                {
                    if (j == 0)
                    {
                        for (int k = 0; k < 4; k++)
                        {
                            keyMatrix[k, j] = Temp[(k + 1) % 4, j + 3];
                        }
                        for (int l = 0; l < 4; l++)
                        {
                            string val1 = keyMatrix[l, j][0].ToString();
                            string val2 = keyMatrix[l, j][1].ToString();
                            int temp1 = Convert.ToInt32(val1, 16);
                            int temp2 = Convert.ToInt32(val2, 16);
                            keyMatrix[l, j] = SBOX[temp1, temp2];
                        }
                        for (int i = 0; i < 4; i++)
                        {
                            TempMatrix1[i, j] = Convert.ToInt32(keyMatrix[i, j], 16);
                            TempMatrix2[i, j] = Convert.ToInt32(Temp[i, j], 16);
                            TempResult[i, j] = TempMatrix1[i, j] ^ TempMatrix2[i, j] ^ intRcon[i, count];
                            keyMatrix[i, j] = Convert.ToString(TempResult[i, j], 16);
                            if (keyMatrix[i, j].Length == 1)
                            {
                                keyMatrix[i, j] = "0" + Convert.ToString(TempResult[i, j], 16);
                            }

                        }
                        count++;
                    }
                    else
                    {
                        for (int m = 0; m < 4; m++)
                        {
                            TempMatrix1[m, j] = Convert.ToInt32(keyMatrix[m, j - 1], 16);
                            TempMatrix2[m, j] = Convert.ToInt32(Temp[m, j], 16);
                            TempResult[m, j] = TempMatrix1[m, j] ^ TempMatrix2[m, j];
                            keyMatrix[m, j] = Convert.ToString(TempResult[m, j], 16);
                            if (keyMatrix[m, j].Length == 1)
                            {
                                keyMatrix[m, j] = "0" + Convert.ToString(TempResult[m, j], 16);
                            }
                        }
                    }

                }
                result.Add(keyMatrix);
                KeyRound++;

            }

            int key_Rounds = result.Count - 1;
            string[,] cipherResultMatrix = AddRoundKey(cipherMatrix, result[key_Rounds]);
            key_Rounds--;
            // 9 rounds ///
            while (round < 9)
            {
                cipherResultMatrix = InverseShiftRows(cipherResultMatrix);
                cipherResultMatrix = InverseSubBytes(cipherResultMatrix);
                cipherResultMatrix = AddRoundKey(cipherResultMatrix, result[key_Rounds]);
                cipherResultMatrix = InverseMixColumns(cipherResultMatrix);


                key_Rounds--;
                round++;
            }
            // final round ///
            cipherResultMatrix = InverseShiftRows(cipherResultMatrix);
            cipherResultMatrix = InverseSubBytes(cipherResultMatrix);
            cipherResultMatrix = AddRoundKey(cipherResultMatrix, result[key_Rounds]);

            string plainText = "0x";
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    plainText += cipherResultMatrix[i, j];
                }
            }
            return plainText;

        }


        AES_techniques obj = new AES_techniques();
        public override string Encrypt(string mainPlain, string mainKey)
        {
            string plainText = mainPlain.Remove(0, 2);//remove 0x from plain text
            string key = mainKey.Remove(0, 2);//remove 0x from key 
            char[] pt = new char[plainText.Length];
            char[] kt = new char[key.Length];
            pt = plainText.ToArray();
            kt = key.ToArray();
            //List<string> mainCipher = new List<string>();
            string mainCipher="0x";
            string[,] plainMAT = new string[4, 4];
            string[,] keyMAT = new string[4, 4];
            int counter = 0, key_counter = 0;
            for (int count1 = 0; count1 < 4; count1++)
            {
                for (int count2 = 0; count2 < 4; count2++)//fill the matrix coulmn wise
                {
                    plainMAT[count2, count1] = pt[counter].ToString() + pt[counter + 1].ToString();//put plain in matrex
                    keyMAT[count2, count1] = kt[counter].ToString() + kt[counter + 1].ToString();//put key in matrex
                    counter += 2;
                }
            }
            string[,] res_Sub = obj.subBytes(plainMAT);
            string[,] res_Shift = obj.ShiftRows(res_Sub);
            string[,] res_Mix = obj.Mix_Colomn(res_Shift);
            string[,] res_RoundKey = obj.AddRoundKey(res_Mix, keyMAT);
            counter = 0;
            string[] new_key_array = obj.expand_key(mainKey);
            string[,] new_Key = new string[4, 4];
            int count1111 = 0;
            plainMAT = obj.AddRoundKey(plainMAT, keyMAT);
            while (count1111 < 9)
            {
                String[,] new_Plain = obj.subBytes(plainMAT);
                res_Shift = obj.ShiftRows(new_Plain);
                res_Mix = obj.Mix_Colomn(res_Shift);
                kt = new_key_array[key_counter].ToArray();
                for (int count2 = 0; count2 < 4; count2++)
                {
                    for (int count3 = 0; count3 < 4; count3++)
                    {
                        new_Key[count3, count2] = kt[counter].ToString() + kt[counter + 1].ToString();
                        counter += 2;
                    }
                }
                key_counter++;
                counter = 0;
                res_RoundKey = obj.AddRoundKey(res_Mix, new_Key);
                plainMAT = res_RoundKey;
                count1111++;
            }
            plainMAT = obj.subBytes(plainMAT);
            res_Shift = obj.ShiftRows(plainMAT);
            for (int count1 = 0; count1 < 4; count1++)
            {
                for (int count2 = 0; count2 < 4; count2++)
                {
                    kt = new_key_array[key_counter].ToArray();
                    new_Key[count2, count1] = kt[counter].ToString() + kt[counter + 1].ToString();
                    counter += 2;
                }
            }
            res_RoundKey = obj.AddRoundKey(res_Shift, new_Key);
            for (int count1 = 0; count1 < 4; count1++)
            {
                for (int count2 = 0; count2 < 4; count2++)
                {
                    mainCipher += res_RoundKey[count2, count1];
                }
            }
            mainCipher.Remove(0, 2);
            return mainCipher;
        }
    }
}
