using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string chars = "abcdefghijklmnopqrstuvwxyz";
            string key = "";
            string p = "";
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int i = 0;
            while (i < 4)
            {
                p += plainText[i];
                i++;
            }
            int p_t = plainText.Length;
            int j = 0;
            while (j < p_t)
            {
                key += chars[((chars.IndexOf(cipherText[j]) - chars.IndexOf(plainText[j])) + 26) % 26];
                j++;
            }
            int index = key.IndexOf(p);
            key = key.Remove(index);
            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string chars = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string P_T = "";
            String K_S = "";
            string T = "";
            int count = 0;
            int i = 0;
            while (i < key.Length)
            {
                K_S += key[i];
                i++;
            }
            int j = 0;
            while (j < K_S.Length)
            {
                T += chars[((chars.IndexOf(cipherText[j]) + 26) - chars.IndexOf(K_S[j])) % 26];
                j++;
            }

            int index = K_S.Length;
            int x = 0;
            while (x < T.Length)
            {
                K_S += T[count];
                count++;
                x++;
            }

            while (K_S.Length != cipherText.Length)
            {
                int a = 0;
                while (a < K_S.Length - T.Length)
                {
                    T += chars[((chars.IndexOf(cipherText[index]) + 26) - chars.IndexOf(K_S[index])) % 26];
                    index++;
                    K_S += T[count];
                    count++;
                    if (K_S.Length == cipherText.Length)
                    {
                        break;
                    }
                    a++;
                }


            }
            int b = 0;
            while (b < cipherText.Length)
            {
                P_T += chars[((chars.IndexOf(cipherText[b]) + 26) - chars.IndexOf(K_S[b])) % 26];
                b++;
            }

            return P_T.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            plainText = plainText.ToUpper();
            key = key.ToUpper();

            string K_S = "";
            if (plainText.Length != key.Length)
            {
                int sub = plainText.Length - key.Length;

                K_S = key;
                int i = 0;
                while (i < sub)
                {
                    K_S = K_S + plainText[i];
                    i++;
                }

            }
            else if (plainText.Length == key.Length)
            {
                K_S = key;
            }
            //////////////////////////////////////////
            string C_T = "";
            int j = 0;
            while (j < plainText.Length)
            {
                int changed_value1 = chars.IndexOf(plainText[j]);
                int changed_value2 = chars.IndexOf(K_S[j]);

                int indx = (changed_value1 + changed_value2) % 26;

                C_T += chars[indx];
                j++;
            }

            return C_T;
        }
    }
}