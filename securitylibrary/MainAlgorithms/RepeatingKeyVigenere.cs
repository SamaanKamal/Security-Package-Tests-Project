using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        int i = 0;
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string alphabet_character = "abcdefghijklmnopqrstuvwxyz";
            string key = "";
            int index = 0;
            bool checker = false;
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int count = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                key += alphabet_character[((alphabet_character.IndexOf(cipherText[i]) - alphabet_character.IndexOf(plainText[i])) + 26) % 26];
            }
            for (int i = 1; i < key.Length; i++)
            {
                if (key[i] == key[count])
                {
                    index = i;
                    //count++;
                    if (key[i + 1] == key[count + 1])
                    {
                        //count++;
                        if (key[i + 2] == key[count + 2])
                        {
                            //count++;
                            if (key[i + 3] == key[count + 3])
                            {
                                //count++;
                                checker = true;
                                break;
                            }
                        }
                    }
                }
                //count++;
            }
            Console.WriteLine(index);
            if (checker)
            {
                key = key.Remove(index);
            }
            return key.ToUpper();
        }

        public string Decrypt(string cipherText, string key)
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string P_T = "";
            string Key_stream = "";
            int c_len = cipherText.Length;
            int k_len = key.Length;
            //int i = 0;
            if (c_len > k_len)
            {
                int sub = c_len - k_len;
                Key_stream = key;
                int j = 0;
                while (j < sub)
                {
                    Key_stream = Key_stream + Key_stream[j];
                    j++;
                }

            }
            else if (c_len == k_len)
            {
                Key_stream = key;
            }
            int i = 0;
            while (i < c_len)
            {
                P_T += chars[((chars.IndexOf(cipherText[i]) + 26) - chars.IndexOf(Key_stream[i])) % 26];
                i++;
            }
            return P_T.ToUpper();

        }

        public string Encrypt(string plainText, string key)
        {

            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            plainText = plainText.ToUpper();
            key = key.ToUpper();

            string K_S = "";
            int p_len = plainText.Length;
            int k_len = key.Length;
            if (p_len > k_len)
            {
                int sub = p_len - k_len;

                K_S = key;
                int j = 0;
                while (j < sub)
                {
                    K_S = K_S + K_S[j];
                    j++;
                }
            }
            else if (p_len == k_len)
            {
                K_S = key;
            }

            string E_T = "";
            int i = 0;
            while (i < p_len)
            {
                int changed_value1 = chars.IndexOf(plainText[i]);
                int changed_value2 = chars.IndexOf(K_S[i]);

                int indx = (changed_value1 + changed_value2) % 26;

                E_T += chars[indx];
                i++;
            }
            return E_T;
        }
    }
}