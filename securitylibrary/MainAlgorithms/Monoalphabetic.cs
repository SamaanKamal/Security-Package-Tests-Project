using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        int index, x;
        public string Analyse(string plainText, string cipherText)
        {
            x = 0;
            string alphabet_character = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            alphabet_character = alphabet_character.ToLower();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char[] key = new char[26];
            do
            {
                key[x] = ' ';// intialize the array as empty
                x++;
            } while (x < 26);
            x = 0;
            while (x < plainText.Length)
            {
                int j = 0;
                while (j < alphabet_character.Length)
                {
                    if (plainText[x] == alphabet_character[j])
                    { key[j] = cipherText[x]; }    //start filling up the key table with cipher charcters by the  index of the alphbet 
                    j++;
                }
                x++;
            }
            for (int i = 0; i < 26; i++)
            {
                if (plainText[0] == alphabet_character[i])
                {
                    index = i + 1;    // loop on the alphbet to know the index of the start element of the key,also add 1 on it
                    break;
                }
            }
            string temp = " ";
            for (int i = index; i < 26; i++)    // loop on the alphabet starting from the "index" (index of first element in the key +1) to check if the charcter is not in the key table
            {
                if (!key.Contains(alphabet_character[i]))
                { temp += alphabet_character[i]; }
            }
            for (int i = 0; i < index - 1; i++)     // loop on the alphabet starting from 0 to index -1 to check if the charcter is not in the key table
            {
                if (!key.Contains(alphabet_character[i]))
                { temp += alphabet_character[i]; }
            }
            int counter = 0;
            for (int i = 0; i < 26; i++)  // loop to continue filing up the key table with the string of the charcters of the alphabet 
            {
                if (key[i] == ' ')
                {
                    key[i] = temp[counter];
                    counter++;
                }
            }
            return new string(key).ToLower();
        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            char[] buffer = key.ToCharArray();//convert a key to char array because of the function index of use char array but not string.
            char[] alphabet_character = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            char[] dcyalphs = new char[cipherText.Length];
            index = -1;
            x = 0;
            while (x < cipherText.Length)
            {
                if (cipherText[x] != ' ')
                {
                    index = Array.IndexOf(buffer, cipherText[x]);
                    if (index != -1)
                    { dcyalphs[x] = alphabet_character[index]; }
                }
                else
                { dcyalphs[x] = ' '; }
                x++;
            }
            return new string(dcyalphs);
        }
        public string Encrypt(string plainText, string key)
        {
            x = 0;//declared global scope
            index = -1;
            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            char[] encalphs = new char[plainText.Length];
            while (x < plainText.Length)
            {
                if (plainText[x] != ' ')
                {
                    index = Array.IndexOf(alphabet, plainText[x]);
                    if (index != -1)
                    { encalphs[x] = key[index]; }
                }
                else
                { encalphs[x] = ' '; }
                x++;
            }
            return new string(encalphs);
        }
        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            String freqAlphabet = "ETAOINSRHLDCUMFPGWYBVKXJQZ";
            freqAlphabet = freqAlphabet.ToLower();
            cipher = cipher.ToUpper();
            string Plain_text = "";
            Dictionary<char, int> sortedAlphabetByFreq = new Dictionary<char, int>();  //dictionary to sort the charcters: key is charcter , value is its frequency
            SortedDictionary<char, char> cipherFreqChars = new SortedDictionary<char, char>(); // dictionary to add charcters: key is cipher charcter, value is its frequency charcter 
            int count = 0, k = 0;
            while (k < cipher.Length)
            {
                if (sortedAlphabetByFreq.ContainsKey(cipher[k]))
                {
                    sortedAlphabetByFreq[cipher[k]] = sortedAlphabetByFreq[cipher[k]] + 1; // increasing the frequncy value
                }
                else
                {
                    sortedAlphabetByFreq.Add(cipher[k], 1); // add the new key and its  frequency value
                }
                k++;
            }
            sortedAlphabetByFreq = sortedAlphabetByFreq.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value); // to order the dictionary in decreasing order depended on its frequency value
            foreach (var item in sortedAlphabetByFreq)
            {
                cipherFreqChars.Add(item.Key, freqAlphabet[count]);  // filing  up the dicitonary with key is cipher charcter, value is its frequency charcter 
                count++;
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                Plain_text += cipherFreqChars[cipher[i]];  //filing up the plain with frequency charcter based on cipher 
            }
            return Plain_text.ToLower();
        }
    }
}