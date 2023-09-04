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
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES obj = new DES();

        public string TripleDesEnc(string plainText, string key)
        {
            throw new NotImplementedException();

        }

        public string TripleDesDec(string cipherText, string key)
        {
            throw new NotImplementedException();

        }


        public string Decrypt(string cipherText, List<string> key)
        {
            //throw new NotImplementedException();
            string x = "";

            x = obj.Decrypt(cipherText, key[1]);
            x = obj.Encrypt(x, key[0]);
            x = obj.Decrypt(x, key[1]);

            return x;

        }

        public string Encrypt(string plainText, List<string> key)
        {
            //throw new NotImplementedException();
            string y = "";

            y = obj.Encrypt(plainText, key[0]);
            y = obj.Decrypt(y, key[1]);
            y = obj.Encrypt(y, key[0]);

            return y;

        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
