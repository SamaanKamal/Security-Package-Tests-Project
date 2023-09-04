using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    class AES_techniques
    {
        byte[,] Rcon = new byte[10, 4]
                               {
                                   {0x01, 0x00, 0x00, 0x00},
                                   {0x02, 0x00, 0x00, 0x00},
                                   {0x04, 0x00, 0x00, 0x00},
                                   {0x08, 0x00, 0x00, 0x00},
                                   {0x10, 0x00, 0x00, 0x00},
                                   {0x20, 0x00, 0x00, 0x00},
                                   {0x40, 0x00, 0x00, 0x00},
                                   {0x80, 0x00, 0x00, 0x00},
                                   {0x1b, 0x00, 0x00, 0x00},
                                   {0x36, 0x00, 0x00, 0x00}  };
        byte[,] Sbox_inbyte = new byte[16, 16]
                 {
           // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f 
           {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
           {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
           {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
           {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
           {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
           {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
           {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
           {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
           {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
           {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
           {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
           {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
           {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
           {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
           {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
           {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};


        string[,] sbox_instring = new string[16, 16] {
                { "63" ,"7c" ,"77" ,"7b" ,"f2" ,"6b" ,"6f" ,"c5" ,"30" ,"01" ,"67" ,"2b" ,"fe" ,"d7" ,"ab" ,"76"},
                { "ca" ,"82" ,"c9" ,"7d" ,"fa" ,"59" ,"47" ,"f0" ,"ad" ,"d4" ,"a2" ,"af" ,"9c" ,"a4" ,"72" ,"c0"},
                { "b7" ,"fd" ,"93" ,"26" ,"36" ,"3f" ,"f7" ,"cc" ,"34" ,"a5" ,"e5" ,"f1" ,"71" ,"d8" ,"31" ,"15"},
                { "04" ,"c7" ,"23" ,"c3" ,"18" ,"96" ,"05" ,"9a" ,"07" ,"12" ,"80" ,"e2" ,"eb" ,"27" ,"b2" ,"75"},
                { "09" ,"83" ,"2c" ,"1a" ,"1b" ,"6e" ,"5a" ,"a0" ,"52" ,"3b" ,"d6" ,"b3" ,"29" ,"e3" ,"2f" ,"84"},
                { "53" ,"d1" ,"00" ,"ed" ,"20" ,"fc" ,"b1" ,"5b" ,"6a" ,"cb" ,"be" ,"39" ,"4a" ,"4c" ,"58" ,"cf"},
                { "d0" ,"ef" ,"aa" ,"fb" ,"43" ,"4d" ,"33" ,"85" ,"45" ,"f9" ,"02" ,"7f" ,"50" ,"3c" ,"9f" ,"a8"},
                { "51" ,"a3" ,"40" ,"8f" ,"92" ,"9d" ,"38" ,"f5" ,"bc" ,"b6" ,"da" ,"21" ,"10" ,"ff" ,"f3" ,"d2"},
                { "cd" ,"0c" ,"13" ,"ec" ,"5f" ,"97" ,"44" ,"17" ,"c4" ,"a7" ,"7e" ,"3d" ,"64" ,"5d" ,"19" ,"73"},
                { "60" ,"81" ,"4f" ,"dc" ,"22" ,"2a" ,"90" ,"88" ,"46" ,"ee" ,"b8" ,"14" ,"de" ,"5e" ,"0b" ,"db"},
                { "e0" ,"32" ,"3a" ,"0a" ,"49" ,"06" ,"24" ,"5c" ,"c2" ,"d3" ,"ac" ,"62" ,"91" ,"95" ,"e4" ,"79"},
                { "e7" ,"c8" ,"37" ,"6d" ,"8d" ,"d5" ,"4e" ,"a9" ,"6c" ,"56" ,"f4" ,"ea" ,"65" ,"7a" ,"ae" ,"08"},
                { "ba" ,"78" ,"25" ,"2e" ,"1c" ,"a6" ,"b4" ,"c6" ,"e8" ,"dd" ,"74" ,"1f" ,"4b" ,"bd" ,"8b" ,"8a"},
                { "70" ,"3e" ,"b5" ,"66" ,"48" ,"03" ,"f6" ,"0e" ,"61" ,"35" ,"57" ,"b9" ,"86" ,"c1" ,"1d" ,"9e"},
                { "e1" ,"f8" ,"98" ,"11" ,"69" ,"d9" ,"8e" ,"94" ,"9b" ,"1e" ,"87" ,"e9" ,"ce" ,"55" ,"28" ,"df"},
                { "8c" ,"a1" ,"89" ,"0d" ,"bf" ,"e6" ,"42" ,"68" ,"41" ,"99" ,"2d" ,"0f" ,"b0" ,"54" ,"bb" ,"16"}};


        public  string[] expand_key(string key)
        {
            List<byte> ByteOfKey = new List<byte>();
            string[] ArrOfKey = new string[10];
            List<string> key_list = new List<string>();
            List<string> coulmn = new List<string>();
            List<string> shift_list = new List<string>();
            List<string> list_afterSbox = new List<string>();
            List<byte> Hexa_one = new List<byte>();
            List<byte> Hexa_two = new List<byte>();
            string ColShift = "";
            string ByteValue = "";
            string key_values_string = "";
            for (int i = 0; i < 10; i++)
            {
                key_list = build_key(key);
                coulmn = CreateMatrixandGetLastCol(key_list);
                shift_list = shif_column(coulmn);
                ColShift = string.Join("", shift_list.ToArray());
                Hexa_one = strtobyte(ColShift);
                list_afterSbox = Sbox_fun(Hexa_one);
                ByteValue = string.Join("", list_afterSbox.ToArray());
                Hexa_two = strtobyte(ByteValue);
                key_values_string = string.Join("", key_list.ToArray());
                ByteOfKey = strtobyte(key_values_string);
                key = newestMat(ByteOfKey, Hexa_two, i);
                ArrOfKey[i] = key;
            }
            return ArrOfKey;
        }
        public List<string> build_key(string key)
        {
            key = key.ToUpper();
            List<string> ListOfKey = new List<string>();
            if (key.Length % 2 != 1)//odd num
            {
                int index = key.IndexOf('X');
                key = key.Substring(index + 1);
            }
            else//even num
            {
                key = key.Remove(0, 2);//remove 0x from key   
            }
            int count = 0;
            string temp = "";
            foreach (char part in key)
            {
                temp += part;
                count++;
                if (count == 2)
                {
                    ListOfKey.Add(temp);
                    temp = "";
                    count = 0;
                }
            }
            if (temp != "")
                ListOfKey.Add(temp);
            return ListOfKey;
        }

        private  List<string> shif_column(List<string> column)
        {
            List<string> temp = new List<string>();
            temp.Add(column[1]);// = last_col_list[1];
            temp.Add(column[2]);
            temp.Add(column[3]);
            temp.Add(column[0]);
            return temp;
        }
        public  List<string> Sbox_fun(List<byte> Hexa)//shift col
        {

            List<string> content = new List<string>();
            for (int count = 0; count < Hexa.Count; count++)
            {
                int decimal_value = Sbox_inbyte[Hexa[count] >> 4, Hexa[count] & 0x0f];
                string value = DecimalToHexadecimal(decimal_value);
                if (value.Length == 1)
                {
                    value = "0" + value;
                    content.Add(value);
                }
                else
                {
                    content.Add(value);
                }
            }
            return content;
        }

        public  string newestMat(List<byte> key_list_byte, List<byte> hexres2, int index)
        {
            List<string> ListOfString_Xor = new List<string>();
            List<byte> Byte_Xor = new List<byte>();
            string stringXOR = "";

            for (int i = 0; i < 4; i++)
            {
                int value_Xor = key_list_byte[i] ^ hexres2[i] ^ Rcon[index, i & 0x0f];
                string stringOfHexa = DecimalToHexadecimal(value_Xor);
                if (stringOfHexa.Length == 1)
                {
                    stringOfHexa = "0" + stringOfHexa;
                    ListOfString_Xor.Add(stringOfHexa);
                }
                else
                {
                    ListOfString_Xor.Add(stringOfHexa);
                }
            }
            stringXOR = string.Join("", ListOfString_Xor.ToArray());
            Byte_Xor = strtobyte(stringXOR);
            for (int i = 4; i < 8; i++)
            {
                int value_Xor = key_list_byte[i] ^ Byte_Xor[i - 4];
                string String_hexa = DecimalToHexadecimal(value_Xor);
                if (String_hexa.Length == 1)
                {
                    String_hexa = "0" + String_hexa;
                    ListOfString_Xor.Add(String_hexa);
                }
                else
                {
                    ListOfString_Xor.Add(String_hexa);
                }

            }
            stringXOR = string.Join("", ListOfString_Xor.ToArray());
            Byte_Xor = strtobyte(stringXOR);
            for (int i = 8; i < 12; i++)
            {
                int value_Xor = key_list_byte[i] ^ Byte_Xor[i - 4];
                string stringOfHexa = DecimalToHexadecimal(value_Xor);
                if (stringOfHexa.Length == 1)
                {
                    stringOfHexa = "0" + stringOfHexa;
                    ListOfString_Xor.Add(stringOfHexa);
                }
                else
                {
                    ListOfString_Xor.Add(stringOfHexa);
                }
            }
            stringXOR = string.Join("", ListOfString_Xor.ToArray());
            Byte_Xor = strtobyte(stringXOR);
            for (int i = 12; i < 16; i++)
            {
                int value_Xor = key_list_byte[i] ^ Byte_Xor[i - 4];
                string stringOfHexa = DecimalToHexadecimal(value_Xor);
                if (stringOfHexa.Length == 1)
                {
                    stringOfHexa = "0" + stringOfHexa;
                    ListOfString_Xor.Add(stringOfHexa);
                }
                else
                {
                    ListOfString_Xor.Add(stringOfHexa);
                }
            }
            stringXOR = string.Join("", ListOfString_Xor.ToArray());
            return stringXOR;
        }
        public  string DecimalToHexadecimal(int Decimal)
        {
            if (Decimal < 1)
                return "0";
            string StringOfHexa = "";
            char ss;
            for (int Hexa = Decimal; Decimal > 0; Decimal /= 16)
            {
                Hexa = Decimal % 16;

                if (Hexa < 10)
                {
                    ss = Convert.ToChar(Hexa + 48);
                    StringOfHexa = StringOfHexa.Insert(0, ss.ToString());
                }
                else
                {
                    ss = Convert.ToChar(Hexa + 55);
                    StringOfHexa = StringOfHexa.Insert(0, ss.ToString());
                }
            }
            return StringOfHexa;
        }

        public  List<byte> strtobyte(string value)
        {
            Dictionary<string, byte> hexindex = new Dictionary<string, byte>();
            for (int i = 0; i <= 255; i++)
                hexindex.Add(i.ToString("X2"), (byte)i);

            List<byte> hexres = new List<byte>();
            if (value.Length % 2 == 1)
            {
                string r = value.Insert(value.Length - 1, "0");
                for (int i = 0; i < r.Length; i += 2)
                {
                    hexres.Add(hexindex[r.Substring(i, 2)]);
                }
            }
            else
            {
                for (int i = 0; i < value.Length; i += 2)
                {
                    hexres.Add(hexindex[value.Substring(i, 2)]);
                }
            }
            return hexres;
        }
        public  UInt32 xtime(UInt32 x)
        {
            x = ((x << 1) ^ (((x >> 7) & 1) * 0x1b));

            return x;
        }
        public  UInt32 multiply(UInt32 x, UInt32 y)
        {
            UInt32 r;
            r = (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x)))
                  ^ ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));

            return r;
        }
        public  List<string> CreateMatrixandGetLastCol(List<string> key_list)
        {
            string[,] matrix = new string[4, 4];
            int c = 0;
            int col = 0;
            int row = 0;
            for (int i = 0; i < 16; i++)
            {
                matrix[row, col] = key_list[c];
                c++;
                row++;
                if (row == 4)
                {
                    col++;
                    row = 0;
                }
            }
            List<string> L_columnShifting = new List<string>();
            for (int i = 0; i < 4; i++)
            {
                L_columnShifting.Add(matrix[i, 3]);
            }
            return L_columnShifting;
        }
        public  string[] SubBox(string[] w)
        {
            string[] newa = new string[4];
            UInt32[] dd = new UInt32[4];
            for (int i = 0; i < 4; i++)
            {
                dd[i] = Convert.ToUInt32(w[i], 16);
            }
            for (int i = 0; i < 4; i++)
            {
                UInt32 ii = (dd[i] & 0xf0) >> 4;
                UInt32 jj = dd[i] & 0x0f;
                newa[i] = sbox_instring[ii, jj];
            }
            return newa;
        }


        public  string[,] subBytes(string[,] matrx)
        {
            string[] m = new string[4];
            string[,] matrex = new string[4, 4];
            int index = 0;
            for (int j = 0; j < 4; j++)//row
            {
                for (int i = 0; i < 4; i++)//col
                {
                    m[index] = matrx[i, j];
                    index++;
                    if (i == 3)
                    {
                        string[] str = SubBox(m);
                        index = 0;
                        for (int row = 0; row < 4; row++)
                        {
                            matrex[row, j] = str[index];
                            index++;
                        }
                    }
                }
                index = 0;
            }
            return matrex;
        }
        public  string[,] ShiftRows(string[,] matrx)
        {
            int shift;
            string[,] matrex = new string[4, 4];
            string[,] Buffer = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Buffer[j, i] = matrx[j, i];
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    shift = (i + j) % 4;
                    matrex[i, j] = Buffer[i, shift];
                }
            }
            return matrex;
        }
        public  string[,] Mix_Colomn(string[,] Mat)
        {
            UInt32[,] matrix = new UInt32[4, 4];
            string[,] matrix_S = new string[4, 4];
            UInt32[,] Buffer = new UInt32[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Buffer[i, j] = Convert.ToUInt32(Mat[i, j], 16);
                }
            }

            for (int col = 0; col < 4; col++)
            {
                matrix[0, col] = (multiply(Buffer[0, col], 2) ^ multiply(Buffer[1, col], 3) ^
                                            multiply(Buffer[2, col], 1) ^ multiply(Buffer[3, col], 1));

                matrix[1, col] = (multiply(Buffer[0, col], 1) ^ multiply(Buffer[1, col], 2) ^
                                            multiply(Buffer[2, col], 3) ^ multiply(Buffer[3, col], 1));

                matrix[2, col] = (multiply(Buffer[0, col], 1) ^ multiply(Buffer[1, col], 1) ^
                                            multiply(Buffer[2, col], 2) ^ multiply(Buffer[3, col], 3));

                matrix[3, col] = (multiply(Buffer[0, col], 3) ^ multiply(Buffer[1, col], 1) ^
                                            multiply(Buffer[2, col], 1) ^ multiply(Buffer[3, col], 2));
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix_S[i, j] = Convert.ToString(matrix[i, j], toBase: 16);
                    if (matrix_S[i, j].Length == 1)
                    {
                        matrix_S[i, j] = "0" + Convert.ToString(matrix[i, j], toBase: 16);
                    }
                    else if (matrix_S[i, j].Length == 3)
                    {
                        char[] str = (Convert.ToString(matrix[i, j], toBase: 16)).ToArray();
                        matrix_S[i, j] = (str[1].ToString() + str[2].ToString());
                    }
                }
            }
            return matrix_S;
        }
        public  string[,] AddRoundKey(string[,] plain, string[,] key)
        {
            string[,] Round_Matrix = new string[4, 4];
            UInt32[,] plain_Matrix = new UInt32[4, 4];
            UInt32[,] key_Matrix = new UInt32[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain_Matrix[i, j] = Convert.ToUInt32(plain[i, j], 16);
                    key_Matrix[i, j] = Convert.ToUInt32(key[i, j], 16);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Round_Matrix[i, j] = Convert.ToString((plain_Matrix[i, j] ^ key_Matrix[i, j]), toBase: 16);
                    if (Round_Matrix[i, j].Length == 1)
                    {
                        Round_Matrix[i, j] = "0" + Convert.ToString((plain_Matrix[i, j] ^ key_Matrix[i, j]), toBase: 16);
                    }
                }
            }
            return Round_Matrix;
        }
    }
}
