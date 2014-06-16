namespace ArtisanCode.SimpleAesEncryption
{
    public interface IMessageDecryptor
    {
        /// <summary>
        /// Decrypts the specified cypher text.
        /// </summary>
        /// <param name="cypherText">The cypherText.</param>
        /// <returns>The plaintext decrypted version of the cypher text</returns>
        string Decrypt(string cypherText);

        /// <summary>
        /// Decrypts a log message.
        /// </summary>
        /// <param name="logMessage">The log message to decrypt.</param>
        /// <returns>The log message with the encrypted strings replaced with the plaintext equivalent</returns>
        string DecyptMessage(string logMessage);
    }
}