using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.DiffieHellman;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int euler_n = (p - 1) * (q - 1);
            int C = power(M, e, n);
            return C;
        }
        public AES.ExtendedEuclid multi_inv = new AES.ExtendedEuclid();
        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int euler_n = (p - 1) * (q - 1);
            int M = power(C, m_inverse(e, euler_n), n);
            return M;
        }
        public int m_inverse(int e, int alpha_n)//to compute d
        {
            return multi_inv.GetMultiplicativeInverse(e, alpha_n); ;
        }
        public int power(int _M, int _e, int _n)
        {
            int result = 1;
            for (int i = 0; i < _e; i++)
            {
                result = (result * _M) % _n;
            }
            return result;
        }
    }
}
