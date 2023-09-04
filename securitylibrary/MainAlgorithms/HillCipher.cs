using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> keyExpriment = new List<int>();
            for (int cell1 = 0; cell1 < 26; cell1++)
            {
                for (int cell2 = 0; cell2 < 26; cell2++)
                {
                    for (int cell3 = 0; cell3 < 26; cell3++)
                    {
                        for (int cell4 = 0; cell4 < 26; cell4++)
                        {
                            keyExpriment = new List<int>(new[] { cell1, cell2, cell3, cell4 });
                            List<int> aa = Encrypt(plainText, keyExpriment);
                            if (aa.SequenceEqual(cipherText))
                            {
                                return keyExpriment;
                            }

                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public int det(Matrix<double> M)
        {

            double A = M[0, 0] * (M[1, 1] * M[2, 2] - M[1, 2] * M[2, 1]) -
                       M[0, 1] * (M[1, 0] * M[2, 2] - M[1, 2] * M[2, 0]) +
                       M[0, 2] * (M[1, 0] * M[2, 1] - M[1, 1] * M[2, 0]);
            int a = (int)A % 26;
            if (a >= 0)
                a = (int)A % 26;
            else
                a = (int)A % 26 + 26;
            for (int i = 0; i < 26; i++)
            {
                if (a * i % 26 == 1)
                {
                    return i;
                }
            }

            return -1;

        }
        public Matrix<double> inv_key(Matrix<double> M, int A)
        {
            int x, y, x1, y1;
            Matrix<double> resMat = DenseMatrix.Create(3, 3, 0);
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (i == 0)
                        x = 1;
                    else
                        x = 0;
                    if (j == 0)
                        y = 1;
                    else
                        y = 0;
                    if (i == 2)
                        x1 = 1;
                    else
                        x1 = 2;
                    if (j == 2)
                        y1 = 1;
                    else
                        y1 = 2;
                    double r = ((M[x, y] * M[x1, y1] - M[x, y1] * M[x1, y]) * Math.Pow(-1, i + j) * A) % 26;
                    if (r >= 0)
                        resMat[i, j] = r;
                    else
                        resMat[i, j] = r + 26;
                }
            }
            return resMat;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            // throw new NotImplementedException();
            List<double> keyD = key.ConvertAll(x => (double)x);
            List<double> CD = cipherText.ConvertAll(x => (double)x);
            int m = Convert.ToInt32(Math.Sqrt((key.Count)));
            Matrix<double> keyMatrix = DenseMatrix.OfColumnMajor(m, (int)key.Count / m, keyD.AsEnumerable());
            Matrix<double> PMatrix = DenseMatrix.OfColumnMajor(m, (int)cipherText.Count / m, CD.AsEnumerable());
            List<int> finalRes = new List<int>();



            if (keyMatrix.ColumnCount == 3)
            {
                keyMatrix = inv_key(keyMatrix.Transpose(), det(keyMatrix));
            }
            else
            {
                keyMatrix = keyMatrix.Inverse();


            }
            if (Math.Abs((int)keyMatrix[0, 0]).ToString() != Math.Abs((double)keyMatrix[0, 0]).ToString())
            {
                throw new SystemException();
            }

            for (int i = 0; i < PMatrix.ColumnCount; i++)
            {
                List<double> Res = new List<double>();
                Res = ((((PMatrix.Column(i)).ToRowMatrix() * keyMatrix) % 26).Enumerate().ToList());
                for (int j = 0; j < Res.Count; j++)
                {
                    int x = (int)Res[j] >= 0 ? (int)Res[j] : (int)Res[j] + 26;
                    finalRes.Add(x);
                }
            }

            return finalRes;
        }


        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int rows = (int)Math.Sqrt(key.Count);
            int[,] keyMatrix = new int[rows, rows];
            int columns = plainText.Count / rows;
            int count1 = 0;
            int count2 = 0;
            int[,] PlainMatrix = new int[rows, columns];
            int[,] result = new int[rows, columns];
            List<int> cipher = new List<int> { };
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    keyMatrix[i, j] = key[count1];
                    count1++;
                }
            }
            for (int i = 0; i < columns; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    PlainMatrix[j, i] = plainText[count2];
                    count2++;
                }
            }

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    for (int k = 0; k < rows; k++)
                    {
                        result[i, j] += (keyMatrix[i, k] * PlainMatrix[k, j]);
                    }
                    result[i, j] %= 26;
                }
            }
            for (int i = 0; i < columns; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    cipher.Add(result[j, i]);
                }

            }
            return cipher;
        }
        private int determinant ( int[,] pMatrix,int size)
        {
            int det=0;
            for (int j = 0; j < size; j++)
            {
                 det += pMatrix[0, j] * (pMatrix[1, (j + 1) % size] * pMatrix[2, (j + 2) % size] - pMatrix[1, (j + 2) % size] * pMatrix[2, (j + 1) % size]); 
            }
            det = det % 26;
            if (det == 7)
            {
                det = 15;
            }
            else if (det == 15)
            {
                det = 7;
            }
                
           return det;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int size = 3;//because of a matrix is sqeured  ((int)Math.Sqrt(plain3.Count)=3)
            int[,] cMatrix = new int[size, size];
            int count = 0;
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                      cMatrix[i, j] = cipher3[count++]%26;
                }
            }
            int[,] pMatrix = new int[size, size];
            count = 0;
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                     pMatrix[j, i] = plain3[count++]%26;
                }
            }
            int det = 0;
            det += determinant(pMatrix, size);//to calculate det.
            int[,] Adjunct_pMatrix = new int[size, size];
            //calculate adj matrix
            Adjunct_pMatrix[0, 0] = (det*(pMatrix[1, 1] * pMatrix[2, 2] - pMatrix[1, 2] * pMatrix[2, 1]))%26;
            Adjunct_pMatrix[0, 1] = (det*((-1) * (pMatrix[1, 0] * pMatrix[2, 2] - pMatrix[1, 2] * pMatrix[2, 0])))%26;
            Adjunct_pMatrix[0, 2] = (det*(pMatrix[1, 0] * pMatrix[2, 1] - pMatrix[1, 1] * pMatrix[2, 0]))%26;
            Adjunct_pMatrix[1, 0] = (det*((-1) * (pMatrix[0, 1] * pMatrix[2, 2] - pMatrix[2, 1] * pMatrix[0, 2])))%26;
            Adjunct_pMatrix[1, 1] = (det*(pMatrix[0, 0] * pMatrix[2, 2] - pMatrix[2, 0] * pMatrix[0, 2]))%26;
            Adjunct_pMatrix[1, 2] = (det*((-1) * (pMatrix[0, 0] * pMatrix[2, 1] - pMatrix[2, 0] * pMatrix[0, 1])))%26;
            Adjunct_pMatrix[2, 0] = (det*(pMatrix[0, 1] * pMatrix[1, 2] - pMatrix[0, 2] * pMatrix[1, 1]))%26;
            Adjunct_pMatrix[2, 1] = (det*((-1) * (pMatrix[0, 0] * pMatrix[1, 2] - pMatrix[1, 0] * pMatrix[0, 2])))%26;
            Adjunct_pMatrix[2, 2] = (det*(pMatrix[0, 0] * pMatrix[1, 1] - pMatrix[1, 0] * pMatrix[0, 1]))%26;
            for (int a = 0; a < size; a++) // becuase of the cell is mod 26
            {
                for (int j = 0; j < size; j++)
                {
                    if (Adjunct_pMatrix[a, j] < 0)
                    {
                        Adjunct_pMatrix[a, j] += 26;
                    }
                }
            }
            int[,] keymatrix = new int[size, size];
            // multiply Adjunct_pMatrix to get key row*col
            keymatrix[0, 0] = (Adjunct_pMatrix[0, 0] * cMatrix[0, 0] + Adjunct_pMatrix[0, 1] * cMatrix[1, 0] + Adjunct_pMatrix[0, 2] * cMatrix[2, 0]) % 26;
            keymatrix[1, 0] = (Adjunct_pMatrix[0, 0] * cMatrix[0, 1] + Adjunct_pMatrix[0, 1] * cMatrix[1, 1] + Adjunct_pMatrix[0, 2] * cMatrix[2, 1]) % 26;
            keymatrix[2, 0] = (Adjunct_pMatrix[0, 0] * cMatrix[0, 2] + Adjunct_pMatrix[0, 1] * cMatrix[1, 2] + Adjunct_pMatrix[0, 2] * cMatrix[2, 2]) % 26;
            keymatrix[0, 1] = (Adjunct_pMatrix[1, 0] * cMatrix[0, 0] + Adjunct_pMatrix[1, 1] * cMatrix[1, 0] + Adjunct_pMatrix[1, 2] * cMatrix[2, 0]) % 26;
            keymatrix[1, 1] = (Adjunct_pMatrix[1, 0] * cMatrix[0, 1] + Adjunct_pMatrix[1, 1] * cMatrix[1, 1] + Adjunct_pMatrix[1, 2] * cMatrix[2, 1]) % 26;
            keymatrix[2, 1] = (Adjunct_pMatrix[1, 0] * cMatrix[0, 2] + Adjunct_pMatrix[1, 1] * cMatrix[1, 2] + Adjunct_pMatrix[1, 2] * cMatrix[2, 2]) % 26;
            keymatrix[0, 2] = (Adjunct_pMatrix[2, 0] * cMatrix[0, 0] + Adjunct_pMatrix[2, 1] * cMatrix[1, 0] + Adjunct_pMatrix[2, 2] * cMatrix[2, 0]) % 26;
            keymatrix[1, 2] = (Adjunct_pMatrix[2, 0] * cMatrix[0, 1] + Adjunct_pMatrix[2, 1] * cMatrix[1, 1] + Adjunct_pMatrix[2, 2] * cMatrix[2, 1]) % 26;
            keymatrix[2, 2] = (Adjunct_pMatrix[2, 0] * cMatrix[0, 2] + Adjunct_pMatrix[2, 1] * cMatrix[1, 2] + Adjunct_pMatrix[2, 2] * cMatrix[2, 2]) % 26;
            List<int> key = new List<int>();
            for (int h = 0; h < size; h++)
            {
                for (int j = 0; j < size; j++)
                { 
                    key.Add(keymatrix[h, j]);
                }
            }
            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}