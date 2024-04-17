using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace SecreteKeysTop
{
    public class CripAES
    {
        private static string fileName =  Guid.NewGuid().ToString();

        public static string GenerateSecretKey()
        {
            byte[] key = new Byte[32];

            var random = RandomNumberGenerator.Create();

            random.GetBytes(key);

            return Convert.ToBase64String(key);
        }

        public static void Criptograph(string plainText, byte[] key)
        {

            if (plainText == null || plainText.Length <= 0)
            {
                throw new ArgumentNullException("plainText");
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("Key");
            }

            using Aes aesAlg = Aes.Create();
            aesAlg.Key = key;

            aesAlg.GenerateIV();

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);


            using FileStream fileStream = new(fileName, FileMode.OpenOrCreate);
            fileStream.Write(aesAlg.IV, 0, aesAlg.IV.Length);

            using CryptoStream csEncrypt = new(fileStream, encryptor, CryptoStreamMode.Write);
            using StreamWriter swEncrypt = new(csEncrypt);
            swEncrypt.WriteLine(plainText);
        }

        public static void Discriptograph(byte[] key)
        {
            using FileStream fileStream = new(fileName, FileMode.Open);

            using Aes aesAlg = Aes.Create();

            byte[] iv = new byte[aesAlg.IV.Length];
            int numBytesToRead = aesAlg.IV.Length;

            int numBytesRead = 0;
            while (numBytesToRead > 0)
            {
                int n = fileStream.Read(iv, numBytesRead, numBytesToRead);
                if (n == 0) break;

                numBytesRead += n;
                numBytesToRead -= n;
            }

            using CryptoStream cryptoStream = new(fileStream, aesAlg.CreateDecryptor(key, iv), CryptoStreamMode.Read);
            using StreamReader decryptReader = new(cryptoStream);
            string decryptedMessage = decryptReader.ReadToEnd();

            Console.WriteLine($"The decrypted original message: {decryptedMessage}");

        }
    }
}