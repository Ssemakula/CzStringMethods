using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace CzStringMethods
{
    public class UserPassword
    {
        public string? HashedPassword { get; set; }
        public string? Salt { get; set; }
    }

    public class CzEncryption
    {
        /// <summary>
        /// Get the encrypted password
        /// </summary>
        /// <param name="plainTextPassword"></param>
        /// <param name="keyLength"></param>
        /// <param name="iterations"></param>
        /// <returns></returns>
        public static UserPassword GetPasswordHash(string plainTextPassword, int keyLength = 32, int iterations = 10000)
        {
            // Generate a random salt
            byte[] salt = new byte[16];
            RandomNumberGenerator.Fill(salt); // Secure random salt

            // Use the non-obsolete constructor of Rfc2898DeriveBytes with HashAlgorithmName.SHA256
            using (var pbkdf2 = new Rfc2898DeriveBytes(plainTextPassword, salt, iterations, HashAlgorithmName.SHA256))
            {
                byte[] keyBytes = pbkdf2.GetBytes(keyLength); // Get the derived key

                // Convert salt and derived key to Base64 strings for storage
                string saltString = Convert.ToBase64String(salt);
                string hashedPassword = Convert.ToBase64String(keyBytes);

                return new UserPassword { HashedPassword = hashedPassword, Salt = saltString };
            }
        }

        /// <summary>
        /// Checks whether a password is valid
        /// </summary>
        /// <param name="plainTextPassword"></param>
        /// <param name="storedHash"></param>
        /// <param name="storedSalt"></param>
        /// <param name="keyLength"></param>
        /// <param name="iterations"></param>
        /// <returns></returns>
        public static bool VerifyPassword(string plainTextPassword, string storedHash, string storedSalt, int keyLength = 32, int iterations = 10000)
        {
            // Convert the stored salt back to a byte array
            byte[] salt = Convert.FromBase64String(storedSalt);

            // Use the same PBKDF2 function to derive the key again
            using (var pbkdf2 = new Rfc2898DeriveBytes(plainTextPassword, salt, iterations, HashAlgorithmName.SHA256))
            {
                byte[] keyBytes = pbkdf2.GetBytes(keyLength); // Derive the key from the input password

                // Convert the derived key to Base64 for comparison
                string derivedKeyString = Convert.ToBase64String(keyBytes);

                // Compare the newly derived key to the stored hash
                return derivedKeyString == storedHash;
            }
        }

        /// <summary>
        /// Encrypts a string using the key phrase
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="encryptionKey"></param>
        /// <returns>Encrypted string</returns>
        public static string SecureEncrypt(string plainText, string encryptionKey)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(encryptionKey);
                aesAlg.GenerateIV(); // Generate a random IV for each encryption

                ICryptoTransform encryptor = aesAlg.CreateEncryptor();

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    // Combine IV and ciphertext for storage
                    byte[] iv = aesAlg.IV;
                    byte[] encryptedBytes = msEncrypt.ToArray();
                    byte[] result = new byte[iv.Length + encryptedBytes.Length];
                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(encryptedBytes, 0, result, iv.Length, encryptedBytes.Length);

                    return Convert.ToBase64String(result);
                }
            }
        }

        /// <summary>
        /// Descrypts cypher text using the key phrase
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="encryptionKey"></param>
        /// <returns>Decrypted string</returns>
        public static string SecureDecrypt(string cipherText, string encryptionKey)
        {
            byte[] combined = Convert.FromBase64String(cipherText);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(encryptionKey);
                byte[] iv = new byte[aesAlg.BlockSize / 8];
                byte[] encryptedBytes = new byte[combined.Length - iv.Length];

                Buffer.BlockCopy(combined, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(combined, iv.Length, encryptedBytes, 0, encryptedBytes.Length);

                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor();

                try
                {
                    using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                return srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
                catch (CryptographicException)
                {
                    return string.Empty;
                }
            }
        }

        /// <summary>
        /// Encrypts a string with a generated keyphrase
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="lValue"></param>
        /// <returns>Encrypted string</returns>
        public static string EncryptString(string plainText, int lValue = 32)
        {
            string keyPhrase = GetKeyPhrase(plainText, lValue);
            return SecureEncrypt(plainText, keyPhrase);

        }

        /// <summary>
        /// Generates Key Phrase from string
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="keyLength"></param>
        /// <param name="powerValue"></param>
        /// <returns>String of length <c>keyLength</c></returns>
        /// <remarks>Will return the same string for a string.length keyLength combination</remarks>
        public static string GetKeyPhrase(string plainText, int keyLength = 32, int powerValue = 32)
        {
            string result;
            BigInteger returnValue = BigInteger.Pow(plainText.Length, powerValue);
            string tempResult = returnValue.ToString("X");
            
            result = GetHexValue(tempResult, keyLength);

            return result;
        }

        /// <summary>
        /// Gets Key Phrase from String securely 
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="keyLength"></param>
        /// <param name="iterations"></param>
        /// <returns>Key Phrase</returns>
        /// <remarks>Same input, same output</remarks>
        public static string GetKeyPhraseDterm(string plainText, int keyLength = 32, int iterations = 10000)
        {
            // Use a fixed salt derived from the input text (e.g., hashed plainText)
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] salt = sha256.ComputeHash(Encoding.UTF8.GetBytes(plainText)); // Derive salt from the plainText

                // Limit salt size to 16 bytes (truncate if necessary)
                Array.Resize(ref salt, 16);

                // Use the non-obsolete constructor of Rfc2898DeriveBytes with HashAlgorithmName.SHA256
                using (var pbkdf2 = new Rfc2898DeriveBytes(plainText, salt, iterations, HashAlgorithmName.SHA256))
                {
                    byte[] keyBytes = pbkdf2.GetBytes(keyLength); // Get the desired number of bytes

                    // Convert the byte array to a Base64 string
                    string base64Key = Convert.ToBase64String(keyBytes);
                    if (base64Key.Length > keyLength)
                    {
                        return base64Key[..keyLength]; // Truncate if too long
                    }
                    else if (base64Key.Length < keyLength)
                    {
                        return base64Key.PadRight(keyLength, '='); // Pad if too short
                    }
                    else
                    {
                        return base64Key;
                    }
                }
            }
        }


        /// <summary>
        /// Gets Key Phrase from String securely
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="keyLength"></param>
        /// <param name="iterations"></param>
        /// <returns></returns>
        public static string GetSecureKeyPhrase(string plainText, int keyLength = 32, int iterations = 10000)
        {
            // Use RandomNumberGenerator to generate a secure random salt
            byte[] salt = new byte[16];
            RandomNumberGenerator.Fill(salt); // Generates a secure random number for the salt

            // Include password length in the salt for variability based on length
            byte[] lengthBytes = BitConverter.GetBytes(plainText.Length);
            for (int i = 0; i < lengthBytes.Length; i++)
            {
                salt[i] ^= lengthBytes[i]; // XOR password length into salt for uniqueness
            }

            // Use the non-obsolete constructor of Rfc2898DeriveBytes with HashAlgorithmName.SHA256
            using (var pbkdf2 = new Rfc2898DeriveBytes(plainText, salt, iterations, HashAlgorithmName.SHA256))
            {
                byte[] keyBytes = pbkdf2.GetBytes(keyLength); // keySize: 16, 24, or 32 for AES-128, AES-192, AES-256

                // Convert the byte array to a Base64 string
                string base64Key = Convert.ToBase64String(keyBytes);
                if (base64Key.Length > keyLength)
                {
                    return base64Key[..keyLength]; // Truncate if too long
                }
                else if (base64Key.Length < keyLength)
                {
                    return base64Key.PadRight(keyLength, '='); // Pad if too short
                }

                return base64Key;
            }
        }

        /// <summary>
        /// Non-secure encryption
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static string EncryptSs(string plainText)
        {
            string EncryptionKey = "ThisismySeedText";
            string InitializationVector = "1234567890123456";

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(EncryptionKey);
                aesAlg.IV = Encoding.UTF8.GetBytes(InitializationVector);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        /// <summary>
        /// Non-secure decryption
        /// </summary>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static string DecryptSs(string cipherText)
        {
            string EncryptionKey = "ThisismySeedText";
            string InitializationVector = "1234567890123456";
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(EncryptionKey);
                aesAlg.IV = Encoding.UTF8.GetBytes(InitializationVector);

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        //--------------------Private functions---------------------------------------------------------//
        /// <summary>
        /// trims or expands a hex number to the required length
        /// </summary>
        /// <param name="hexNumber"></param>
        /// <param name="n"></param>
        /// <returns></returns>
        private static string GetHexValue(string hexNumber, int n = 32) //n = required length
        {
            string hexValue = "";
            if (n > hexNumber.Length)
            {
                for (int i = 0; i < n - hexNumber.Length; i++)
                    hexValue = hexValue += "0";
                hexValue = hexNumber + hexValue;
            }
            else if (n == hexNumber.Length)
                hexValue = hexNumber;
            else
                hexValue = hexNumber.Remove(n);
            return hexValue;
        }
    }
}
