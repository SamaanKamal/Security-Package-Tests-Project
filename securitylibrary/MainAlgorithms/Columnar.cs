using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int numberOfRows = 0, numberOfColumns = 0, counter1 = 0, counter2 = 0;
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int check = 0, x = 1;
            do
            {
                if (plainText.Length % x == 0)
                {
                    numberOfColumns = x;
                }
                x++;
            } while (x < 8);
            numberOfRows = plainText.Length / numberOfColumns;
            char[,] plainText_matrix = new char[numberOfRows, numberOfColumns];
            char[,] cipherText_metrix = new char[numberOfRows, numberOfColumns];
            List<int> key = new List<int>(numberOfColumns);


            for (int indx1 = 0; indx1 < numberOfRows; indx1++)
            {
                for (int indx2 = 0; indx2 < numberOfColumns; indx2++)
                {
                    if (counter1 < plainText.Length)
                        plainText_matrix[indx1, indx2] = plainText[counter1];
                    if (counter1 >= plainText.Length)
                    {
                        if (plainText_matrix.Length > plainText.Length)
                            plainText_matrix[indx1, indx2] = 'x';
                    }
                    counter1++;
                }
            }

            for (int indx1 = 0; indx1 < numberOfColumns; indx1++)
            {
                for (int indx2 = 0; indx2 < numberOfRows; indx2++)
                {
                    if (counter2 == plainText.Length)
                        break;
                    cipherText_metrix[indx2, indx1] = cipherText[counter2];
                    counter2++;
                }
            }

            for (int indx1 = 0; indx1 < numberOfColumns; indx1++)
            {
                for (int indx2 = 0; indx2 < numberOfColumns; indx2++)
                {
                    for (int indx3 = 0; indx3 < numberOfRows; indx3++)
                    {
                        if (plainText_matrix[indx3, indx1] == cipherText_metrix[indx3, indx2])
                        {
                            check++;
                        }
                        if (check == numberOfRows)
                            key.Add(indx2 + 1);
                    }
                    check = 0;
                }
            }
            if (key.Count == 0)
            {
                for (int indx = 0; indx < numberOfColumns + 2; indx++)
                {
                    key.Add(0);
                }
            }
            return key;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string plainText = "";
            int columns = key.Count;
            int rows = (int)Math.Round((decimal)cipherText.Length / columns);
            List<int> key_storage = new List<int>();
            int count = 1;
            for (int i = 0; i < columns; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    if (key[j] == count)//to store place for key.
                    {
                        key_storage.Add (j);
                        count++;
                        break;
                    }
                }
            }
            int PlainTextIndex = 0;
            char[,] cipherMatrix = new char[rows, columns];
            for (int i = 0; i < columns; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    if (PlainTextIndex < cipherText.Length)
                    {
                        cipherMatrix[j, i] = cipherText[PlainTextIndex];
                        PlainTextIndex++;
                    }
                }
            }
            char[,] originalMessageMatrix = new char[rows, columns];
            for (int i = 0; i < columns; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    originalMessageMatrix[j, key_storage[i]] = cipherMatrix[j, i];
                }
            }

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    plainText += originalMessageMatrix[i, j];
                }
            }

            return plainText.ToUpper();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int columns = key.Count;
            int rows = (int)Math.Ceiling((double)plainText.Length / columns);
            int area = rows * columns;
            if (plainText.Length != area)
            {
                int x = area - plainText.Length;
                string appender = new string('x', x);
                plainText += appender;
            }
            List<List<char>> table = new List<List<char>>();
            Dictionary<int, string> MatrixElemnts = new Dictionary<int, string>();
            string CT = "";
            for (int i = 0; i < rows; i++)
            {
                table.Add(new List<char>());
            }

            int counter = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns && counter < plainText.Length; j++)
                {
                    table[i].Add(plainText[counter]);
                    counter++;
                }
            }

            for (int i = 0; i < columns; i++)
            {
                string tmp = "";
                for (int j = 0; j < rows; j++)
                {
                    tmp += table[j][i];
                    MatrixElemnts[key[i]] = tmp;
                }
            }

            for (int i = 1; i <= MatrixElemnts.Count; i++)
            {
                CT += MatrixElemnts[i];
            }
            //Console.WriteLine(CT);
            return CT.ToUpper();
        }
    }
}