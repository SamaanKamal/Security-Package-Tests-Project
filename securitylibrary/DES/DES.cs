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
    public class DES : CryptographicTechnique
    {
        //initial permutation to the plain text
        int[,] initial_permutation = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };
        //inverse initial permutation^-1  >>> IP^-1
        int[,] inverse_initial_permutation = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };

        //permuted_choice_1 // permute key and divide to C & D
        int[,] permuted_choice_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };
        //permuted choice_2 // permute  C & D  but not now ..when??.. after do  left circular shift for them and do that by no. of Round
        int[,] permuted_choice_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

        //>>> expand the 32-bits of s-boxes to 48-bits
        //48-bits expansion permutation
        int[,] expansion_permutation = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

        //permutation to the S-box at all
        int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
               
        //========================================================================================================================================
        //using in encription
        int[,] s_box1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        int[,] s_box2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        int[,] s_box3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        int[,] s_box4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        int[,] s_box5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        int[,] s_box6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        int[,] s_box7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        int[,] s_box8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

        //using in decryption
        //S-Boxes permutations
        int[,] s_bx1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        int[,] s_bx2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        int[,] s_bx3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        int[,] s_bx4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        int[,] s_bx5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        int[,] s_bx6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        int[,] s_bx7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        int[,] s_bx8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
        //========================================================================================================================================

        public override string Decrypt(string cipherText, string key)
        {
            string Binary_key;
            string temp_key = "";
            string Binary_cipher;
            string Right_m = "";
            string Left_m = "";
            string _1st_half_s;
            string _2nd_half_s;
            List<string> list_1;
            List<string> list_2;



            Binary_key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            Binary_cipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');

            int m = Binary_cipher.Length / 2;

            //
            for (int i = 0; i < 8; i++)
            {
                for (int k = 0; k < 7; k++)
                {
                    temp_key = temp_key + Binary_key[permuted_choice_1[i, k] - 1];
                }
            }
            //

            _1st_half_s = temp_key.Substring(0, 28);
            _2nd_half_s = temp_key.Substring(28, 28);

            for (int i = 0; i < m / 2; i++)
            {
                Right_m = Right_m + Binary_cipher[i + Binary_cipher.Length / 2];
                Left_m = Left_m + Binary_cipher[i];
            }

            //premutate key by pc-1

            list_1 = new List<string>();
            list_2 = new List<string>();




            string tmp_str = "";
            for (int i = 0; i <= 16; i++)
            {
                list_1.Add(_1st_half_s);
                list_2.Add(_2nd_half_s);
                tmp_str = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    tmp_str = tmp_str + _1st_half_s[0];
                    _1st_half_s = _1st_half_s.Remove(0, 1);
                    _1st_half_s = _1st_half_s + tmp_str;
                    tmp_str = "";
                    tmp_str = tmp_str + _2nd_half_s[0];
                    _2nd_half_s = _2nd_half_s.Remove(0, 1);
                    _2nd_half_s = _2nd_half_s + tmp_str;
                }

                else
                {
                    tmp_str = tmp_str + _1st_half_s.Substring(0, 2);
                    _1st_half_s = _1st_half_s.Remove(0, 2);
                    _1st_half_s = _1st_half_s + tmp_str;
                    tmp_str = "";
                    tmp_str = tmp_str + _2nd_half_s.Substring(0, 2);
                    _2nd_half_s = _2nd_half_s.Remove(0, 2);
                    _2nd_half_s = _2nd_half_s + tmp_str;
                }
            }

            List<string> keys = new List<string>();
            for (int i = 0; i < list_2.Count; i++)
            {
                keys.Add(list_1[i] + list_2[i]);
            }

            //key1 --> key16 by pc-2
            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                temp_key = "";
                tmp_str = "";
                tmp_str = keys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        temp_key = temp_key + tmp_str[permuted_choice_2[i, j] - 1];
                    }
                }

                nkeys.Add(temp_key);
            }

            //premutation by IP for plain text
            string intial_per = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    intial_per = intial_per + Binary_cipher[initial_permutation[i, j] - 1];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = intial_per.Substring(0, 32);
            string r = intial_per.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string EBit = "";
            string exclusive_ork = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int column = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                L.Add(r);
                exclusive_ork = "";
                EBit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                column = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        EBit = EBit + r[expansion_permutation[j, k] - 1];
                    }
                }

                for (int g = 0; g < EBit.Length; g++)
                {
                    exclusive_ork = exclusive_ork + (nkeys[nkeys.Count - 1 - i][g] ^ EBit[g]).ToString();
                }

                for (int z = 0; z < exclusive_ork.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exclusive_ork.Length)
                            t = t + exclusive_ork[y];
                    }

                    sbox.Add(t);
                }

                t = "";
                int s_bx = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    column = Convert.ToInt32(h, 2);
                    if (s == 0)
                        s_bx = s_box1[row, column];

                    else if (s == 1)
                        s_bx = s_box2[row, column];

                    else if (s == 2)
                        s_bx = s_box3[row, column];

                    else if (s == 3)
                        s_bx = s_box4[row, column];

                    else if (s == 4)
                        s_bx = s_box5[row, column];

                    if (s == 5)
                        s_bx = s_box6[row, column];

                    if (s == 6)
                        s_bx = s_box7[row, column];

                    if (s == 7)
                        s_bx = s_box8[row, column];

                    tsb = tsb + Convert.ToString(s_bx, 2).PadLeft(4, '0');
                }

                x = "";
                h = "";

                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp = pp + tsb[P[k, j] - 1];
                    }
                }

                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ l[k]).ToString();
                }

                r = lf;
                l = L[i + 1];
                R.Add(r);
            }

            string right16_left16 = R[16] + L[16];
            string Cipher_text = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    Cipher_text = Cipher_text + right16_left16[inverse_initial_permutation[i, j] - 1];
                }
            }
            string plain_text = "0x" + Convert.ToInt64(Cipher_text, 2).ToString("X").PadLeft(16, '0');
            return plain_text;
        }




        public override string Encrypt(string plainText, string key)
        {

            //using 64-bits block from the plain text and key then combine them in 16 round to convert the plain_Text to Cipher_Text  
            //if there is remaining 64-bits blocks make the above rules again until finishing.....


            //convert plain text to their value in binary then  // Pad left with '0' if no longer text available then// make the result 64-bits block  .... remaining bits will be '0' 
            string Binary_P_text = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            //convert plain text to their value in binary then  // Pad left with '0' if no longer text available then// make the result 64-bits block  .... remaining bits will be '0' 
            string Binary_Key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////   
            //step 1 //
            //divide the plain Text
            string left_half_PT = "";
            string Right_half_PT = "";

            //when starting by entering the round 1 ... we divide the binary plain Text to 2 ... Left And Right
            for (int i = 0; i < Binary_P_text.Length / 2; i++)
            {
                left_half_PT = left_half_PT + Binary_P_text[i];
                Right_half_PT = Right_half_PT + Binary_P_text[i + Binary_P_text.Length / 2];
            }


            //////////////////////////////////////////////////////////////////////////////////////////////////////////////   
            //step 2 // 
            ///////////prepearing the 16 key C & D//////
            //premutate key by permuted choice_1 >> pc_1
            string Temp_key = "";
            // list to take all keys of the 16 rounds
            List<string> C = new List<string>();
            List<string> D = new List<string>();

            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    Temp_key = Temp_key + Binary_Key[permuted_choice_1[i, j] - 1];
                }
            }
            /////so we have 56 values////


            //C and D
            //C take the  first half of result of pc_1 >>(0->28) and D take the second >>(28->56)
            string c = Temp_key.Substring(0, 28);  // (startindex , length)
            string d = Temp_key.Substring(28, 28); // (startindex , length)


            //step ledt circular shift of key////
            string temp_k = "";
            int round = 0;
            //why 17 iteration ... because every shift we do , affect on the next key .. so when we finished the 16 rounds on iterate 15th we apply the last shiffting in the last key  
            while (round <= 16)  // for the 16 rounds preparing the 28-bit   C & D
            {
                C.Add(c);
                D.Add(d);
                temp_k = "";
                if (round == 0 || round == 1 || round == 8 || round == 15) // we make 1 shift in these cases only
                {
                    temp_k = temp_k + c[0]; // store the 1st value in the c in temp
                    c = c.Remove(0, 1); // remove the 1st value in the c // because it's only 1 shift 
                    c = c + temp_k; // so we make the shift // because the value that shifted we add it again in the last of c
                    temp_k = "";                      // do the above rules to d too ....
                    temp_k = temp_k + d[0];
                    d = d.Remove(0, 1);
                    d = d + temp_k;
                }

                else  // we make 2 shifts in remaining cases
                {
                    temp_k = temp_k + c.Substring(0, 2); // store the 1st,2nd values in the c in temp
                    c = c.Remove(0, 2); // remove the 1st,2nd values in the c // because it's 2 shifts
                    c = c + temp_k; // so we make the shift // because the 2 values that shifted we add them again in the last of c
                    temp_k = "";                        // do the above rules to d too ....
                    temp_k = temp_k + d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d = d + temp_k;
                }

                round++;
            }

            /////////////////

            //combine all lists C & D again
            List<string> keys = new List<string>();
            for (int i = 0; i < D.Count; i++)
            {
                keys.Add(C[i] + D[i]);
            }

            //minus 2 form C And 2 form D
            // in pc_2 we neglected 2 keys to be the result 48 
            //premutate keys from key_1 to key_16 by permuted choice_2 >> pc_2
            List<string> n_keys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                Temp_key = "";
                temp_k = "";
                temp_k = keys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        Temp_key = Temp_key + temp_k[permuted_choice_2[i, j] - 1];
                    }
                }

                n_keys.Add(Temp_key); // add each permutation
            }


            ///////////step3//
            //////////////////////////////////////////////////////////////////////////////////////////////////////////
            //premutation by initial permutation (IP) for plain text
            string intial_permutation = "";
            for (int i = 0; i < 8; i++) // 8*8 = 64-bits
            {
                for (int j = 0; j < 8; j++)
                {
                    intial_permutation = intial_permutation + Binary_P_text[initial_permutation[i, j] - 1];
                }
            }

            List<string> lefts_list = new List<string>();   //list for left half of plain text
            List<string> rights_list = new List<string>();   //list for right half of plain text


            string left = intial_permutation.Substring(0, 32);
            string right = intial_permutation.Substring(32, 32);

            lefts_list.Add(left); //add the left half of plain text to the list
            rights_list.Add(right); //add the right half of plain text to the list
            string x = "";
            string h = "";

            string expansion_bit = "";
            string expansion_Xor_key = "";
            List<string> sbox = new List<string>(); // list of S-box

            int row = 0, col = 0;
            string tsb = "", pp = "", lf = "", t = "";

            //////////16 rounds//////////////////////////////////////////////////////////////
            for (int i = 0; i < 16; i++)
            {
                sbox.Clear(); // clear S_box after every round
                lefts_list.Add(right); // give old right of plain to next left   (of the next round)
                expansion_Xor_key = "";
                expansion_bit = "";
                lf = "";
                pp = "";

                tsb = "";
                col = 0;
                row = 0;
                t = "";
                ////>>> expand the 32-bits of right to 48-bits
                //48-bits expansion permutation///////////////////////////////////////////
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        expansion_bit = expansion_bit + right[expansion_permutation[j, k] - 1];
                    }
                }

                // Ex Xor Key
                for (int g = 0; g < expansion_bit.Length; g++)
                {
                    expansion_Xor_key = expansion_Xor_key + (n_keys[i][g] ^ expansion_bit[g]).ToString();
                }

                //S-box step///////////////////////////////////////////////////
                for (int z = 0; z < expansion_Xor_key.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= expansion_Xor_key.Length)
                            t = t + expansion_Xor_key[y];
                    }

                    sbox.Add(t); //add the s-box one by one 
                }
                //////////permutation of s-box step
                t = "";
                int SboX = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5]; //1st and last
                    h = t[1].ToString() + t[2] + t[3] + t[4]; //the remain
                    //convert output to binary
                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    //using S-Box Permutations
                    if (s == 0)
                        SboX = s_bx1[row, col];

                    if (s == 1)
                        SboX = s_bx2[row, col];

                    if (s == 2)
                        SboX = s_bx3[row, col];

                    if (s == 3)
                        SboX = s_bx4[row, col];

                    if (s == 4)
                        SboX = s_bx5[row, col];

                    if (s == 5)
                        SboX = s_bx6[row, col];

                    if (s == 6)
                        SboX = s_bx7[row, col];

                    if (s == 7)
                        SboX = s_bx8[row, col];
                    //so we have 4 bits from 6 by s-box processes
                    tsb = tsb + Convert.ToString(SboX, 2).PadLeft(4, '0');
                }


                //using permutation of s-box at all
                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp = pp + tsb[P[k, j] - 1];
                    }
                }

                //(result of permutation of s-box at all)  Xor left
                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ left[k]).ToString();
                }

                right = lf;    // assign the result of above Xor to right
                left = lefts_list[i + 1];  // add the 2nd left of the 2nd round from the lefts_list to left
                rights_list.Add(right); // we have a result >> it is the right .. now add it to rights_list
            }

            //swapping >> because the orginal that " Left Right " and we swap them so >> "Right Left"
            string Swapping_bits = rights_list[16] + lefts_list[16]; // number of lefts and rights in the lists

            ////final step////////////////////////////////////////////////////////////////////////////////////////////////
            string Cipher_text = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    Cipher_text = Cipher_text + Swapping_bits[inverse_initial_permutation[i, j] - 1];
                }
            }
            string C_T = "0x" + Convert.ToInt64(Cipher_text, 2).ToString("X");

            return C_T;
        }

    }
}
