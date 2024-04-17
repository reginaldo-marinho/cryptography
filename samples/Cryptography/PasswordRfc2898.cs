using System;
using System.Security.Cryptography;

namespace SecreteKeysTop
{
    public sealed class PasswordRfc2898
    {
        public static bool SlowEquals(byte[] a, byte[] b)
        {

            uint diff = (uint)a.Length ^ (uint)b.Length;

            for (int i = 0; i < a.Length && i < b.Length; i++)
            {

                diff |= (uint)(a[i] ^ b[i]);
            }

            return diff == 0;
        }

        public static string GeneratePassword(string password)
        {
            byte[] salt = new Byte[100];

            var random = RandomNumberGenerator.Create();

            random.GetBytes(salt);

            var base64Hash = GeneratePassword(salt, password, 5000);

            return base64Hash;
        }

        private static string GeneratePassword(byte[] salt, string password, int iterations)
        {
            var result = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, 100);

            var base64Hash = Convert.ToBase64String(result);

            return base64Hash;
        }

        public static string GeneratePassword(string password, string salt)
        {

            byte[] saltByte = Convert.FromBase64String(salt);

            var base64Hash = GeneratePassword(saltByte, password, 5000);

            return base64Hash;
        }
    }
}