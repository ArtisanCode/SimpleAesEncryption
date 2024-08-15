namespace ArtisanCode.SimpleAesEncryption
{
    public class EncryptionKeyConfigurationElement
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyConfigurationElement"/> class.
        /// </summary>
        public EncryptionKeyConfigurationElement()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyConfigurationElement"/> class.
        /// </summary>
        /// <param name="keySize">Size of the key.</param>
        /// <param name="key">The key.</param>
        public EncryptionKeyConfigurationElement(int keySize, string key)
        {
            this.KeySize = keySize;
            this.Key = key;
        }

        /// <summary>
        /// Gets or sets the encryption key.
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// Gets or sets the size of the key in bits.
        /// </summary>
        public int KeySize { get; set; } = 256;
    }
}
