using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace FileEncrypt
{
    class HideAndSeek
    {
        static string FileInput;
        static string[] Parameters = new string[4], TypesOfParameters = new string[4];
        static readonly string[] CorrectParameters = { "/k", "/o", "/d", "/v", "/?" };
        static string Key = "", FileOutput = "";

        const ushort LongS = sizeof(Int64) * 8;
        const ushort IntS = sizeof(Int32) * 8;
        const string EncFin = ".enc";
        const string DecFin = ".dec";

        private static Encoding GetEncoding() { return Encoding.UTF8; }


        static void Main(string[] args)
        {
            if (!CheckFirstInput(args)) return;
            if (!FileExists(args[0])) return;

            FileInput = args[0];
            byte[] fileContent = null;

            if (!SetAndCheckParameters(args))
                return;
            IsInforequired();

            if (!CheckKey()) return;
            if (!CheckValidParameters_d_v()) return;

            try
            {
                fileContent = File.ReadAllBytes(FileInput);
            }
            catch (IOException)
            {
                Console.WriteLine("Operation failed");
                return;
            }

            long fileLength = GetLength(fileContent);
            fileContent = Normalize(fileContent);
            
            byte[] finalValue = null;
            bool encrypted = false;

            if (!TypesOfParameters.Contains("/d")) 
            {
                if (TypesOfParameters.Contains("/v"))
                {
                    finalValue = EncryptWithCRC(fileContent, fileLength);
                    encrypted = true;
                }
                else 
                {
                    finalValue = EncryptWithoutCRC(fileContent);
                    encrypted = true;
                }

                if (TypesOfParameters.Contains("/o") && encrypted)
                {
                    if (!FileFill(FileOutput, finalValue)) return;
                    else if (!FileExists(FileOutput)) return;
                }
                else if(encrypted)
                {
                    if (!FileCreateAndFillEncryption(finalValue)) return;
                }
            }
            else
            {
                finalValue = Decryption(fileContent);

                if (BytesArrayIsZero(finalValue)) return;
                else
                {
                    if (TypesOfParameters.Contains("/o"))
                    {

                        if (!FileFill(FileOutput, finalValue)) return;
                        else if (!FileExists(FileOutput)) return;
                    }
                    else
                    {
                        if (!FileCreateAndFillDecryption(finalValue)) return;
                    }
                }
            }

            Console.WriteLine("Operation successful! ");
            Console.ReadKey();
        }

        //   ENCRYPTION FUNCTIONS 
        #region Encryption 
        private static byte[] EncryptWithoutCRC(byte[] fileContent)
        {
            byte[] byteKey = FromHex(Key);

            return FileEncrypt(fileContent, byteKey);
        }

        private static byte[] EncryptWithCRC(byte[] fileContent, long fileLength)
        {
            int CRC_int = CRCOperation(fileContent);
            var X = fileLength.ToString();
            var Y = CRC_int.ToString();

            byte[] CRC = SpecialFormatLong(X);
            byte[] length = SpecialFormatInt(Y);
            
            var list = new List<byte>();
            list.AddRange(fileContent);
            list.AddRange(length);
            list.AddRange(CRC);

            byte[] finalValue = list.ToArray();

            byte[] byteKey = FromHex(Key);
            byte[] encryptedFile = FileEncrypt(finalValue, byteKey);
            return encryptedFile;
        }

        static byte[] FileEncrypt(byte[] byteFile, byte[] byteKey)
        {
            byte[] encrypted = null;
            try
            {
                encrypted = XorOperation(byteFile, byteKey);
            }
            catch (DivideByZeroException)
            {
                Console.WriteLine("Operation failed");
                byte[] zero = MakeZero();
                return zero;
            }
            return encrypted;
        }
        #endregion

        //    DECRYPTION FUNCTIONS
        #region Decryption
        private static byte[] Decryption(byte[] fileContent)
        {
            byte[] byteKey = FromHex(Key);
            byte[] decryptedFile = null;
            try
            {
                decryptedFile = FileDecrypt(fileContent, byteKey);
            }
            catch (DivideByZeroException)
            {
                Console.WriteLine("Operation failed");
                byte[] zero = MakeZero();
                return zero;
            }
            return decryptedFile;
        }

        private static byte[] FileDecrypt(byte[] encryptedFileInput, byte[] key_b)
        {
            byte[] decrypted = XorOperation(encryptedFileInput, key_b);
            int lengthOfFile = decrypted.Length;

            long correctLength = lengthOfFile - LongS - IntS;
            int CRC = CRCOperation(decrypted);

            byte[] zero = MakeZero();
            string zeroStr = Encoding.UTF8.GetString(zero);

            long length = GetLengthValue(decrypted, lengthOfFile, zeroStr);
            if (length == -1) return zero;
            if (!CheckValidEncryption(length, correctLength)) return zero;

            int CRC_actual = GetCRCValue(decrypted, lengthOfFile, zeroStr);
            if (CRC_actual == -1) return zero;
            if (!CheckCRCValid(CRC, CRC_actual)) return zero;

            byte[] correctFile = new byte[correctLength];
            Array.Copy(decrypted, correctFile, correctLength);

            return correctFile;
        }
        #endregion

        //    FILE METHODS
        #region Files
        private static bool FileFill(string fileOutput, byte[] finalValue)
        {
            try
            {
                if (CheckFileInput(fileOutput, false))
                {
                    File.WriteAllBytes(fileOutput, finalValue);
                }
                else return false;
            }
            catch (IOException)
            {
                Console.WriteLine("Operation failed");
                return false;
            }
            return true;
        }

        private static bool FileCreateAndFill(string fileName,  byte[] finalValue) 
        {
            try
            {
                if (CheckFileInput(fileName, false))
                {
                    using (new FileStream(fileName, FileMode.Create, FileAccess.Write)) { }
                    File.WriteAllBytes(fileName, finalValue);
                }
                else return false;
            }
            catch (IOException)
            {
                Console.WriteLine("Operation failed");
                return false;
            }
            return true;
        }

        private static bool FileCreateAndFillDecryption(byte[] finalValue)
        {
            string fileName = DecryptedFileName(FileInput);
            try
            {
                if(!FileCreateAndFill(fileName, finalValue)) return false;
            }
            catch( IOException)
            {
                Console.WriteLine("Operation failed");
                return false;
            }
            return true;
        }

        //    FILE NAME SETUP 

        private static bool FileCreateAndFillEncryption(byte[] finalValue)
        {
            try
            {
                string fileName = FileInput + EncFin;
                if( !FileCreateAndFill(fileName, finalValue)) return false;
            }
            catch (Exception)
            {
                Console.WriteLine("Operation failed");
                return false;
            }
            return true;
        }

        private static string DecryptedFileName(string fileInput)
        {
            int nb = fileInput.Length;
            string efin = EncFin; int finL = efin.Length;
            string dfin = DecFin;
            if( fileInput.Substring(nb - finL) == efin)
            {
                if (fileInput.Substring(0, nb - finL).Contains('.') && (fileInput.Count(x => x == '.') == 2))
                {
                    return fileInput.Substring(0, nb - finL);
                }
            }
            return fileInput + dfin;
        }
        #endregion

        //    PARAMETER SETUP
        #region Parameters
        private static bool SetAndCheckParameters(string[] args)
        {
            ushort normalParam = 2, specialParam = 3;
            for (ushort i = 1; i < args.Length; i++)
            {
                Parameters[i - 1] = args[i];
                string parameterType = args[i].Substring(0, normalParam);

                if ((parameterType == "/k" || parameterType == "/o"))
                {
                    if (!CheckRightParameter_k_o(parameterType, args[i])) return false;

                    TypesOfParameters[i - 1] = parameterType;
                    if (TypesOfParameters[i - 1] == "/k")
                        Key = Parameters[i - 1].Substring(3);
                    else FileOutput = Parameters[i - 1].Substring(specialParam);
                }
                else if (CheckWrongParameter(parameterType, CorrectParameters))
                    return false;
                else TypesOfParameters[i - 1] = parameterType;
            }
            return true;
        }
        #endregion

        //CHECK FOR ERRORS
        #region Input errors
        private static bool CheckWrongParameter(string parameterType, string[] v)
        {
            if (!v.Contains(parameterType))
            {
                Console.WriteLine("Invalid parameter {0}", parameterType);
                return true;
            }
            return false;
        }

        private static bool CheckRightParameter_k_o(string parameterType, string argument)
        {
            if ((parameterType == "/k" || parameterType == "/o")
                         && (argument.Length < 4 || argument.ElementAt(2) != ':'))
            {
                Console.WriteLine("Invalid parameter {0}", parameterType);
                return false;
            }
            return true;
        }

        public static bool CheckFirstInput( string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Input file name not specified");
                return false;
            }

            FileInput = args[0];

            if(!CheckFileInput(FileInput, true))
                return false;

            if (args.Length == 1)
            {
                Console.WriteLine("Key not specified");
                return false;
            }

            return true;
        }


        static bool CheckKey() {
            if (!TypesOfParameters.Contains("/k"))
            {
                Console.WriteLine("Key not specified");
                return false;
            }

            bool isHex = Regex.IsMatch(Key, "^[0-9a-fA-F]+$");
            if (!isHex)
            {
                Console.WriteLine("Invalid key format");
                return false;
            }
            return true;
        }

        static bool CheckValidParameters_d_v() {
            if (TypesOfParameters.Contains("/d") && TypesOfParameters.Contains("/v"))
            {
                Console.WriteLine("Invalid parameter {0}", "/v");
                return false;
            }
            return true;
        }
        static void IsInforequired()
        {
            if (TypesOfParameters.Contains("/?"))
            {
                InformationScreen();
            }
        }

        static bool CheckFileInput(string fileName, bool firstFile)
        {
            if (!(fileName.IndexOfAny(Path.GetInvalidFileNameChars()) > 0) && !firstFile)
            {
                Console.WriteLine("Invalid file name {0} ", fileName);
                return false;
            }
            else if(!(fileName.IndexOfAny(Path.GetInvalidFileNameChars()) > 0)){
                Console.WriteLine("Input file name not specified ");
                return false;
            }
            return true;
        }

        static bool FileExists(string fileName)
        {
            if (!File.Exists(fileName))
            {
                Console.WriteLine("File not found {0} ", fileName);
                return false;
            }
            return true;
        }

        private static bool CheckValidEncryption(long length, long correctLength)
        {
            if (length != correctLength)
            {
                Console.WriteLine("Invalid encryption");
                return false;
            }
            return true;
        }

        private static bool CheckCRCValid(int CRC, int CRC_actual)
        {
            if (CRC != CRC_actual)
            {
                Console.WriteLine("Decrypted data validation failed");
                return false;
            }
            return true;
        }

        #endregion

        #region Compute 
        public static byte[] FromHex(string hex)
        {
            hex = hex.Replace("-", "");
            byte[] raw = new byte[hex.Length / 2];
            for (ushort i = 0; i < raw.Length; i++)
            {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), sizeof(Int16) * 8);
            }
            return raw;
        }

        static byte[] XorOperation(byte[] file, byte[] key)
        {
            byte[] result = new byte[file.Length];
            for (ushort i = 0; i < result.Length; i++)
            {
                ushort j = (ushort)(i % key.Length);
                result[i] = (byte)(file[i] ^ key[j]);
            }
            return result;
        }

        static int CRCOperation(byte[] file)
        {
            int result = SmallValue(file, 0);
            ushort sh = sizeof(Int32);
            if (file.Length < sh)
            {
                return result;
            }
            for (ushort i = sh; i < file.Length; i = (ushort)(i + sh))
            {
                int small = SmallValue(file, i);
                result = (result ^ small);
            }
            return result;
        }
        #endregion
        //HELP FUNCTIONS

        #region Help
        // FOR DIVIDING BYTES IN CRC
        static int SmallValue(byte[] file, ushort index)
        {
            byte[] small = new byte[4];
            for (ushort i = index; i < 4; i++)
            {
                if (i < file.Length)
                {
                    small[i - index] = file[i];
                }
                else
                {
                    small[i - index] = 0;
                }
            }
            return BitConverter.ToInt32(small, 0);
        }

        private static bool BytesArrayIsZero(byte[] bt)
        {
            byte[] zero = MakeZero();

            if (bt.Length == zero.Length && bt[0] == zero[0]) return true;
            return false;
        }

        private static byte[] MakeZero()
        {
            byte[] zero = new byte[1];
            zero[0] = 0;
            return zero;
        } 

        //    Many functions that return bytes use different encoding systems
        //    To make sure the encoding remains the same through the file 
        //    will use the Encogind.UTF8 format and change from string to bytes[] 
        //    for easier debugging
        private static byte[] Normalize(byte[] fileContent)
        {
            var actualValue = Encoding.UTF8.GetString(fileContent);
            return Encoding.UTF8.GetBytes(actualValue);
        }

        private static long GetLength(byte[] fileContent)
        {
            Encoding cod = GetEncoding();
            return (long)(cod.GetString(fileContent).Length);
        }

        //Special Format is used to make sure that during decryption the CRC and Length values have 
        //fixed lengths
        private static byte[] SpecialFormatInt(string X)
        {
            Encoding cod = GetEncoding();
            ushort I = IntS;
            byte[] CRC = new byte[I];
            byte[] val = cod.GetBytes(X);
            int sz = val.Length, j = 0;
            for (ushort i = 0; i < I; i++)
            {
                if (i < I - sz)
                {
                    CRC[i] = 0;
                }
                else
                {
                    CRC[i] = val[j++];
                }
            }
            return CRC;
        }

        private static byte[] SpecialFormatLong(string X)
        {
            Encoding cod = GetEncoding();
            ushort L = LongS;
            byte[] Length = new byte[L];
            byte[] val = cod.GetBytes(X);
            int sz = val.Length, j = 0;
            for (ushort i = 0; i < L; i++)
            {
                if (i < L - sz)
                {
                    Length[i] = 0;
                }
                else
                {
                    Length[i] = val[j++];
                }
            }
            return Length;
        }

        private static long GetLengthValue(byte[] decrypted, int lengthOfFile, string zeroStr)
        {
            int dif = (int)lengthOfFile - LongS;
            byte[] valueOfLength = decrypted.Skip(dif).Take(LongS).ToArray();

            Encoding cod = GetEncoding();
            string strL = cod.GetString(valueOfLength);

            strL = strL.Replace(zeroStr, "").Trim();
            long length = 0;
            try
            {
                length = Int64.Parse(strL);
            }
            catch (FormatException)
            {
                Console.WriteLine("Operation failed");
                return -1;
            }
            return length;
        }

        private static int GetCRCValue(byte[] decrypted, int lengthOfFile, string zeroStr)
        {
            int dif = (int)lengthOfFile - LongS - IntS;
            byte[] CRC_dec = decrypted.Skip(dif).Take(IntS).ToArray();

            Encoding cod = GetEncoding();
            string strC = cod.GetString(CRC_dec);
            strC = strC.Trim().Replace(zeroStr, "");
            int CRC_int = 0;
            try
            {
                CRC_int = Int32.Parse(strC);
            }
            catch (FormatException)
            {
                Console.WriteLine("Operation failed");
                return -1;
            }
            return CRC_int;
        }
        #endregion

        private static void InformationScreen()
        {
            Console.WriteLine("***************       HIDE AND SEEK GUIDE       ***************");
            Console.WriteLine("            Simple encryption/decryption application           ");
            Console.WriteLine("");
            Console.WriteLine(" Write in Command prompt the following line :                  ");
            Console.WriteLine(" HideAndSeek.cs fileInput /k:key [/o:fileOutput] [/d] [/v] [/?]");
            Console.WriteLine("");
            Console.WriteLine(" Rules: ");
            Console.WriteLine(" HideAndSeek.cs is the name of the program.Change if necessary ");
            Console.WriteLine("");
            Console.WriteLine(" fileInput - file to encrypt/decrypt. Change if necessary      ");
            Console.WriteLine("");
            Console.WriteLine(" /k:key - the key for encryption. Has to be a hexadecimal      ");
            Console.WriteLine("");
            Console.WriteLine(" [/o:fileOutput]- file for output. If not provided, another one");
            Console.WriteLine(" will be generated. The following rule applies for the new files: ");
            Console.WriteLine(" File.txt encrypt -> File.txt.enc ");
            Console.WriteLine(" File.txt.enc decrypt -> File.txt ");
            Console.WriteLine(" File.enc decrypt -> File.enc.dec ");
            Console.WriteLine(" File.txt encrypt -> File.txt.dec ");
            Console.WriteLine("");
            Console.WriteLine(" [/d] -> decryption. If not given -> encryption                ");
            Console.WriteLine(" [/v] -> adds a CRC at the end of the encrypted file. Useful   ");
            Console.WriteLine(" to check the validity of the encryption before it is decrypted");
            Console.WriteLine(" Cannot be used in the same time as [/d] ");
            Console.WriteLine("");
            Console.WriteLine(" [/?] Informations ");
            Console.WriteLine("***************************************************************");
            Console.ReadKey();
        }
    }
}
