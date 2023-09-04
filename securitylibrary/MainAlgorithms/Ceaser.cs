using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        int index = 0;

        public string Encrypt(string plainText, int key)
        {
            int length = plainText.Length;
            char[] encryptedMessage = new char[length];
            while (index < length)
            {
                var letter = plainText[index];
                int indletter = Array.IndexOf(alphabet, letter);
                int newIndex = (key + indletter) % 26;
                char newLetter = alphabet[newIndex];
                encryptedMessage[index] = newLetter;
                index++;
            }

            return new string(encryptedMessage);
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int length = cipherText.Length;
            char[] dencryptedMessage = new char[length];
            while (index < length)
            {
                var letter = cipherText[index];
                int indletter = Array.IndexOf(alphabet, letter);
                int newIndex = (indletter - key);
                if (newIndex > 0 && newIndex < 26)
                {
                    newIndex = newIndex + 0; 
                }
                else if (newIndex < 0)
                {
                    newIndex = newIndex + 26; 
                }
                else if (newIndex > 26)
                {
                    newIndex = newIndex - 26; 
                }
                char newLetter = alphabet[newIndex];
                dencryptedMessage[index] = newLetter;
                index++;
            }

            return new string(dencryptedMessage).ToUpper();
        }

        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            key = cipherText[0] - plainText[0];
            if (key < 0)
            {
                key = key + 26; 
            }

            return key;
        }
    }
}