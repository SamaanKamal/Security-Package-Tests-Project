using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        //we made this function (calc_y_k) because the built_in >> math.pow >> return double datatype
        public int calc_y_k(int alpha_, int x_, int q_)
        {
            int result = 1;
            for (int i = 0; i < x_; i++) // calculate alpha power x then mod q 
            {
                result = (result * alpha_) % q_;
            }
            return result;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int yA = calc_y_k(alpha, xa, q);
            int yB = calc_y_k(alpha, xb, q);
            int calc_k1 = calc_y_k(yB, xa, q);
            int calc_k2 = calc_y_k(yA, xb, q);

            List<int> list_Of_Keys = new List<int>();
            list_Of_Keys.Add(calc_k1);
            list_Of_Keys.Add(calc_k2);

            return list_Of_Keys;
        }
    }
}
