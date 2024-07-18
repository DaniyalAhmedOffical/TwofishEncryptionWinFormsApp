using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace TwofishEncryptionWinFormsApp
{
    public class TwofishEncryption
    {
        private const int BlockSize = 16; // 128 bits

        public static byte[] Encrypt(string plainText, byte[] key, byte[] iv)
        {
            var engine = new TwofishEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];

            int length = cipher.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            return outputBytes;
        }

        public static string Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            var engine = new TwofishEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] outputBytes = new byte[cipher.GetOutputSize(cipherText.Length)];

            int length = cipher.ProcessBytes(cipherText, 0, cipherText.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            return Encoding.UTF8.GetString(outputBytes).TrimEnd('\0');
        }

        public static string Encrypt64(string plainText, string keyHex)
        {
            byte[] keyBytes = HexStringToByteArray(keyHex);
            byte[] iv = new byte[BlockSize]; // You may want to use a different IV
            byte[] encrypted = Encrypt(plainText, keyBytes, iv);
            return Convert.ToBase64String(encrypted);
        }

        public static string Decrypt64(string cipherText, string keyHex)
        {
            byte[] keyBytes = HexStringToByteArray(keyHex);
            byte[] iv = new byte[BlockSize]; // You may want to use a different IV
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            return Decrypt(cipherBytes, keyBytes, iv);
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}
