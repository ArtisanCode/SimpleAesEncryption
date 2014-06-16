using System;
using System.IO;
using System.Security.Cryptography;

namespace ArtisanCode.SimpleAesEncryption
{
    public class RijndaelMessageEncryptor : RijndaelMessageHandler, IMessageEncryptor
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageEncryptor"/> class.
        /// </summary>
        /// <remarks>
        /// Reads the configuration directly from the configuration file section: MessageEncryption
        /// </remarks>
        public RijndaelMessageEncryptor()
            : base()
        {

        }
        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageEncryptor"/> class.
        /// </summary>
        /// <param name="configurationSectionName">Name of the configuration section to use.</param>
        public RijndaelMessageEncryptor(string configurationSectionName)
            : base(configurationSectionName)
        {

        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageEncryptor"/> class.
        /// </summary>
        /// <param name="config">The configuration.</param>
        public RijndaelMessageEncryptor(SimpleAesEncryptionConfiguration config)
            : base(config)
        {

        }

        /// <summary>
        /// Encrypts the specified source.
        /// </summary>
        /// <param name="source">The source.</param>
        /// <returns></returns>
        public virtual string Encrypt(string source)
        {
            // Short-circuit encryption for empty strings
            if (string.IsNullOrEmpty(source))
            {
                return string.Empty;
            }

            // Encrypt the string to an array of bytes.
            var output = EncryptStringToBytes(source);

            // Return the Base64 encoded cypher-text along with the (plaintext) unique IV used for this encryption
            return string.Format("{0}{1}{2}", Convert.ToBase64String(output.Item1), CYPHER_TEXT_IV_SEPERATOR, Convert.ToBase64String(output.Item2));
        }

        /// <summary>
        /// Encrypts the string to bytes.
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <remarks>
        /// Original version: http://msdn.microsoft.com/en-us/library/system.security.cryptography.rijndaelmanaged.aspx
        /// 20/05/2014 @ 20:05
        /// </remarks>
        /// <returns>
        /// Item 1: The cyphertext that is generated from the plaintext input
        /// Item 2: The IV used for the encryption algorithm
        /// </returns>
        public virtual Tuple<byte[], byte[]> EncryptStringToBytes(string plainText)
        {
            Tuple<byte[], byte[]> output;

            // Create an RijndaelManaged object with the specified key and IV.
            using (RijndaelManaged cryptoContainer = new RijndaelManaged())
            {
                ConfigureCryptoContainer(cryptoContainer, Configuration);

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = cryptoContainer.CreateEncryptor(cryptoContainer.Key, cryptoContainer.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }

                        output = new Tuple<byte[], byte[]>(msEncrypt.ToArray(), cryptoContainer.IV);
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return output;
        }
    }
}