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
            StringBuilder KeyTemporary = new StringBuilder(key.ToUpper());
            /////////////////////////////////////remove all the repeated characters from the keyword/////////////////////////////////////
            for (int count1 = 0; count1 < KeyTemporary.Length; count1++)
            {
                for (int count2 = 0; count2 < count1; count2++)
                {
                    if (KeyTemporary[count1] == KeyTemporary[count2]) //if a character existed before.
                    {
                        KeyTemporary = KeyTemporary.Remove(count1, 1); //remove(start index , length).
                        count1--;
                        continue;
                    }
                }
            }
            for (int x = 0; x < KeyTemporary.Length; x++)
            {
                if (KeyTemporary[x] == 'J') //store i,j in the same cell.
                {
                    KeyTemporary[x] = 'I';
                }
            }
            //////////////////////////////storing the keyword in the matrix and the rest of the alphabets///////////////////////////////////////
            bool key_stored_boolean = false;
            char[,] mtx = new char[5, 5];
            // stores the key and the rest of the alphabets in the matrix
            char alphabetic_count = 'A';
            for (int r = 0; r < 5; r++)
            {
                for (int c = 0; c < 5; c++)
                {
                    if ((((r * 5) + c) < KeyTemporary.Length) && (key_stored_boolean == false))
                    {
                        mtx[r, c] = KeyTemporary[(r * 5) + c];//convert from 1D to 2D -> (row*n+col) : n=size.
                    }
                    else
                    {
                        key_stored_boolean = true;
                        bool exists_in_keyword = false ;
                        for (int count1 = 0; count1 < KeyTemporary.Length; count1++)// if the current alphabet exists in the keyword or not.
                        {
                            if (alphabetic_count == KeyTemporary[count1]) //if this character exists in key.
                            {
                                exists_in_keyword = true;
                                break;
                            }
                        }
                        if ((exists_in_keyword == false) && (alphabetic_count) != 'J') 
                        {
                            mtx[r, c] = alphabetic_count;//storing it in the matrix
                        }
                        else
                        {
                            c--;
                        }

                        alphabetic_count++;
                    }
                }
            }
            //////////////////////////////////////////////////the decryption///////////////////////////////////////////////////////////////
            StringBuilder buffer_dec = new StringBuilder(cipherText);
            int first_character_row = 0, first_character_col = 0, second_character_row = 0, second_char_col = 0;
            for (int matrix_counter = 0; matrix_counter < buffer_dec.Length; matrix_counter += 2)
            {
                ReturnPositionOfChar(buffer_dec[matrix_counter], ref first_character_row, ref first_character_col, mtx);
                ReturnPositionOfChar(buffer_dec[matrix_counter + 1], ref second_character_row, ref second_char_col, mtx);
                if (first_character_col == second_char_col)
                {
                    buffer_dec[matrix_counter] = mtx[(first_character_row + 4) % 5, first_character_col];
                    buffer_dec[matrix_counter + 1] = mtx[(second_character_row + 4) % 5, second_char_col];
                }
                else if (first_character_row == second_character_row)
                {
                    buffer_dec[matrix_counter] = mtx[first_character_row, (first_character_col + 4) % 5];
                    buffer_dec[matrix_counter + 1] = mtx[second_character_row, (second_char_col + 4) % 5];
                }
                else
                {
                    buffer_dec[matrix_counter] = mtx[first_character_row, second_char_col];
                    buffer_dec[matrix_counter + 1] = mtx[second_character_row, first_character_col];
                }
            }
            ///////////////////////////////dealing with the Last Character ///////////////////////////////////////////////////////////////
            string txt_with_Last_Character = "";
            string cipher_txt = buffer_dec.ToString().ToLower();
            int len = cipher_txt.Length;
            if (cipher_txt[len - 1] == 'x' && (len - 1) % 2 == 1)
            {
                txt_with_Last_Character = cipher_txt.Remove(len - 1, 1);
                for (int i = 0; i < txt_with_Last_Character.Length - 2; i++)
                {
                    if (txt_with_Last_Character[i] == txt_with_Last_Character[i + 2] && txt_with_Last_Character[i + 1] == 'x')
                    {
                        txt_with_Last_Character = txt_with_Last_Character.Remove(i + 1, 1);
                    }
                    i++;
                }
                return txt_with_Last_Character;
            }
            else
            {
                for (int i = 0; i < cipher_txt.Length - 2; i++)
                {
                    if (cipher_txt[i] == cipher_txt[i + 2] && cipher_txt[i + 1] == 'x')
                    {
                        cipher_txt = cipher_txt.Remove(i + 1, 1);
                    }
                    else
                    {
                        i++;
                    }
                }
                return cipher_txt;
            }
        }

        public string Encrypt(string plainText, string key)
        {
            StringBuilder buffer = new StringBuilder(plainText.ToUpper());
            int[] space_indexes = new int[20];
            int space_count = 0;
            int count = 0;
            while (count < buffer.Length)
            {
                if (buffer[count] == ' ')
                {
                    buffer = buffer.Remove(count, 1);
                    space_indexes[space_count] = count;
                    space_count++;
                }
                count++;
            }
            space_indexes[space_count] = -1;//because of a last element is empty ,so last element = -1 ->use it in search.
            count = 0;//update the value of count because reuse it.
            while ( count < buffer.Length)
            {
                if (buffer[count] == 'J')
                {
                    buffer[count] = 'I';
                }
                count++;
            }
            count = 0; 
            while ((count + 1) < buffer.Length)//check on the biger counter
            {
                if (buffer[count] == buffer[count + 1])
                {
                    buffer.Insert(count + 1, "X");
                }
                count =count + 2;
            }
            if ((buffer.Length % 2) == 1)
            {
                buffer.Append("X");
            }         
            StringBuilder KeyTemporary = new StringBuilder(key.ToUpper());
            count = 0;
            while ( count < KeyTemporary.Length)
            {
                if (KeyTemporary[count] == 'J')
                {
                    KeyTemporary[count] = 'I';
                }
                count++;
            }
            for (int i = 0; i < KeyTemporary.Length; i++)
            {
                for (int j = 0; j < i; j++)//check this character existed before or not.
                {
                    if (KeyTemporary[i] == KeyTemporary[j]) //if a character existed before.
                    {
                        KeyTemporary = KeyTemporary.Remove(i, 1); //if exist repeated letter then will be delete this letter.
                        i--;//because this deleted element
                        continue;  
                    }
                }
            }
            int idx=-1;
            char[] small_letter = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            char[] capital_letter = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            int W = 0;
            while ( W < KeyTemporary.Length)
            {
                idx = Array.IndexOf(small_letter, KeyTemporary[W]);
                if (idx!=-1) //if the letter is small letter.
                {
                    KeyTemporary[W] = capital_letter[idx]; //convert it into capital letter.
                }
                W++;
            }
            bool KeyStoreInMatrix = false;
            bool ExsistInKey = false;
            char[,] mtx = new char[5, 5];
            ///////this loop stores the key and store the alphabets in the matrix///////
            char IterationOnAlphabet = 'A';
            for (int r = 0; r < 5;r++)
            {
                for (int c = 0; c < 5; c++)
                {
                    //store the keycharacter in the matrix then store the rest of the alphabets
                    if ((((r * 5) + c) < KeyTemporary.Length) && (KeyStoreInMatrix == false))
                    {
                        mtx[r, c] = KeyTemporary[(r * 5) + c];//convert from 1D to 2D -> (row*n+col) : n=size.
                    }
                    else //if the key is stored so that we have to store the rest of the alphabets
                    {
                        KeyStoreInMatrix = true;
                        ExsistInKey = false;
                        for (int count1 = 0; count1 < KeyTemporary.Length; count1++)
                        {
                            if (IterationOnAlphabet == KeyTemporary[count1]) //check this character exists in the key
                            {
                                ExsistInKey = true;
                                break;
                            }
                        }
                        if ((ExsistInKey == false) && (IterationOnAlphabet != 'J'))// if it character doesn't exist in the key & dosen't j character.
                        {
                            mtx[r, c] =IterationOnAlphabet;//store it in the matrix
                        }
                        else
                        {
                            c--;
                        }

                        IterationOnAlphabet++;
                    }
                }
            }
                                    ////////////////////////////encribtion/////////////////////////////
            int FirstCharRow = 0, FirstCharCol = 0, SecondCharRow = 0, SecondCharCol = 0, cnt = 0;
            while ( cnt < buffer.Length)
            {
                ReturnPositionOfChar(buffer[cnt], ref FirstCharRow, ref FirstCharCol, mtx);
                ReturnPositionOfChar(buffer[cnt + 1], ref SecondCharRow, ref SecondCharCol, mtx);

                if (FirstCharRow != SecondCharRow && FirstCharCol != SecondCharCol)
                {
                    buffer[cnt] = mtx[FirstCharRow, SecondCharCol];
                    buffer[cnt + 1] = mtx[SecondCharRow, FirstCharCol];
                }
                else if (FirstCharRow == SecondCharRow)
                {
                    buffer[cnt] = mtx[FirstCharRow, (FirstCharCol + 1) % 5];
                    buffer[cnt + 1] = mtx[SecondCharRow, (SecondCharCol + 1) % 5];
                }
                else if (FirstCharCol == SecondCharCol)
                {
                    buffer[cnt] = mtx[(FirstCharRow + 1) % 5, FirstCharCol];
                    buffer[cnt + 1] = mtx[(SecondCharRow + 1) % 5, SecondCharCol];
                }
                cnt += 2;
            }
            count = 0;
            while (space_indexes[count] != -1)//last element in this array is -1.
            {
                buffer.Insert(space_indexes[count] + count, " ");
                count++;
            }
            plainText = buffer.ToString();
            return plainText;
        }
        void ReturnPositionOfChar(char element, ref int r, ref int c, char[,] mtx)
        {
            // loop on  the matrix until  find the character and then return its coordinates
            int row_count = 0, char_match_flag = 0;
            do
            {
                for (int col_count = 0; col_count < 5; col_count++)
                {
                    if (mtx[row_count, col_count] == element)
                    {
                        char_match_flag = 1;
                        c = col_count;
                        r = row_count;
                        break;
                    }
                }
                row_count++;
            } while (char_match_flag == 0);
        }
    }
}