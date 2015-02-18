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
    }
}