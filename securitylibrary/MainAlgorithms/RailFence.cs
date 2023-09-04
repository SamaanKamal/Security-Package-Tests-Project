using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            string Encrypted_message = "";
            string orginal_message = "";
            orginal_message = plainText.ToUpper();
            Encrypted_message = cipherText.ToUpper();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (Encrypted_message[1] == orginal_message[i])
                {
                    if (i > 1)
                    {
                        return i;
                    }
                }

            }
            return 0;

        }

        public string Decrypt(string cipherText, int key)
        {
            string plaintext = "";
            int deph = (int)Math.Ceiling((double)cipherText.Length / key); //Ceiling return the smallest int value greater than flaot value 
            //depth : number of rows must be int


            char[,] matrix = new char[key, deph];
            int counterPlain = 0;
            for (int i = 0; i < key; i++)
            {
                if (cipherText[counterPlain] == '\0')
                {
                    break;
                }
                for (int j = 0; j < deph; j++)
                {
                    if (counterPlain < cipherText.Length)
                    {
                        matrix[i, j] = cipherText[counterPlain];
                        counterPlain++;
                    }
                }
            }
            for (int j = 0; j < deph; j++)
            {

                for (int i = 0; i < key; i++)
                {
                    plaintext += matrix[i, j];
                }
            }
            return plaintext.ToUpper();
        }
        public string Encrypt(string plainText, int key)
        {

            plainText = plainText.ToUpper();
            int columns = (int)Math.Ceiling((double)plainText.Length / key);
            //Ceiling return the smallest int value greater than flaot value 
            //depth = key : number of rows must be int

            char[,] matrix = new char[key, columns];
            int counterPlain = 0;
            for (int j = 0; j < columns; j++)
            {
                if (plainText[counterPlain] == '\0')
                {
                    break;
                }
                for (int i = 0; i < key; i++)
                {
                    if (counterPlain < plainText.Length)
                    {
                        matrix[i, j] = plainText[counterPlain];
                        counterPlain++;
                    }
                }
            }
            string Encrypted_message = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    Encrypted_message += matrix[i, j];
                }
            }
            return Encrypted_message.ToUpper();
        }
    }
}
