using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace ArtisanCode.SimpleAesEncryption
{
    public class RijndaelMessageDecryptor : RijndaelMessageHandler, IMessageDecryptor
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageDecryptor"/> class.
        /// </summary>
        /// <remarks>
        /// Reads the configuration directly from the configuration file section: MessageEncryption
        /// </remarks>
        public RijndaelMessageDecryptor()
            : base()
        {

        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageDecryptor"/> class.
        /// </summary>
        /// <param name="configurationSectionName">Name of the configuration section to use.</param>
        public RijndaelMessageDecryptor(string configurationSectionName)
            : base(configurationSectionName)
        {

        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageDecryptor"/> class.
        /// </summary>
        /// <param name="config">The configuration.</param>
        public RijndaelMessageDecryptor(SimpleAesEncryptionConfiguration config)
            : base(config)
        {

        }

        /// <summary>
        /// Decrypts the specified cypherText.
        /// </summary>
        /// <param name="cypherText">The cypherText to decrypt.</param>
        /// <returns>The plaintext decrypted version of the cypher text</returns>
        /// <exception cref="System.ArgumentException">Invalid source string. Unable to determine the correct IV used for the encryption. Please ensure the source string is in the format 'Cypher Text' + CYPHER_TEXT_IV_SEPERATOR + 'IV';source</exception>
        public virtual string Decrypt(string cypherText)
        {
            // Short-circuit decryption for empty strings
            if (string.IsNullOrEmpty(cypherText))
            {
                return string.Empty;
            }

            var primatives = cypherText.Split(new[] { CYPHER_TEXT_IV_SEPERATOR }, StringSplitOptions.RemoveEmptyEntries);

            if (primatives.Length != 2)
            {
                throw new ArgumentException("Invalid cypherText. Unable to determine the correct IV used for the encryption. Please ensure the source string is in the format 'Cypher Text'" + CYPHER_TEXT_IV_SEPERATOR + "'IV'", "source");
            }

            var cypherTextPrimitave = Convert.FromBase64String(primatives[0]);
            var iv = Convert.FromBase64String(primatives[1]);

            return DecryptStringFromBytes(cypherTextPrimitave, iv);
        }


        /// <summary>
        /// Decrypts the string from bytes.
        /// </summary>
        /// <param name="cipherText">The cipher text.</param>
        /// <param name="Key">The key.</param>
        /// <param name="IV">The iv.</param>
        /// <returns></returns>
        /// <remarks>
        /// Original version: http://msdn.microsoft.com/en-us/library/system.security.cryptography.rijndaelmanaged.aspx
        /// 20/05/2014 @ 20:05
        /// </remarks>
        /// <exception cref="System.ArgumentNullException">
        /// cipherText
        /// or
        /// IV
        /// </exception>
        public virtual string DecryptStringFromBytes(byte[] cipherText, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }

            if (IV == null || IV.Length <= 0)
            {
                throw new ArgumentNullException("IV");
            }

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged cryptoContainer = new RijndaelManaged())
            {
                ConfigureCryptoContainer(cryptoContainer, Configuration);

                // Remember to set the IV to the correct value for decryption
                cryptoContainer.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = cryptoContainer.CreateDecryptor(cryptoContainer.Key, cryptoContainer.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }


        /// <summary>
        /// Decrypts a log message.
        /// </summary>
        /// <param name="logMessage">The log message to decrypt.</param>
        /// <returns>
        /// The log message with the encrypted strings replaced with the plaintext equivalent
        /// </returns>
        public virtual string DecyptMessage(string logMessage)
        {
            if (string.IsNullOrWhiteSpace(logMessage))
            {
                return string.Empty;
            }

            // Determine if the log message has multiple lines e.g. is an Exception message
            var logLines = logMessage.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

            if (logLines.Length > 1)
            {
                // Decrypt each line individually and join them together in the same order they appeared
                return string.Join(Environment.NewLine, logLines.Select(x => DecryptLogLine(x)));
            }

            return DecryptLogLine(logLines.First());
        }

        /// <summary>
        /// Decrypts the log line.
        /// </summary>
        /// <param name="logLine">The log line.</param>
        /// <returns>the plaintext representation of the log line</returns>
        public virtual string DecryptLogLine(string logLine)
        {
            // Assume that the message is split by spaces
            var tokens = logLine.Split(new[] { ' ' }, StringSplitOptions.None);

            for (int i = 0; i < tokens.Length; i++)
            {
                // Only attempt to decrypt log messages that contain the cypher / IV separator (??)
                if (tokens[i].Contains(CYPHER_TEXT_IV_SEPERATOR))
                {
                    // If the decryption succeeds, replace the encrypted string with the decrypted message
                    try
                    {
                        var decryptedMessage = Decrypt(tokens[i]);
                        logLine = logLine.Replace(tokens[i], decryptedMessage);
                    }
                    catch
                    {
                        // Do nothing: If the decryption fails, leave the encrypted string in place
                    }
                }
            }

            return logLine;
        }
    }
}