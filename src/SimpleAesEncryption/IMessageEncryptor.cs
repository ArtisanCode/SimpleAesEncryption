namespace ArtisanCode.SimpleAesEncryption
{
    public interface IMessageEncryptor
    {
        /// <summary>
        /// Encrypts the specified source.
        /// </summary>
        /// <param name="source">The source.</param>
        /// <returns>The cypher-text generated from the source</returns>
        string Encrypt(string source);
    }
}