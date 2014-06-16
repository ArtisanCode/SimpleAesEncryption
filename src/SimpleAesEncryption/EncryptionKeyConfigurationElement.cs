using System.Configuration;

namespace ArtisanCode.SimpleAesEncryption
{
    public class EncryptionKeyConfigurationElement : ConfigurationElement
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyConfigurationElement"/> class.
        /// </summary>
        /// <param name="keySize">Size of the key.</param>
        /// <param name="key">The key.</param>
        public EncryptionKeyConfigurationElement(int keySize, string key)
            : base()
        {
            this.KeySize = keySize;
            this.Key = key;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyConfigurationElement"/> class.
        /// </summary>
        public EncryptionKeyConfigurationElement()
            : base()
        {

        }

        /// <summary>
        /// Gets or sets the encryption key.
        /// </summary>
        /// <remarks>
        /// The length of the key needs to be the same as the value defined within the keySize configuration
        /// </remarks>
        /// <value>
        /// The encryption key.
        /// </value>
        [ConfigurationProperty("Key", IsRequired = true)]
        public string Key
        {
            get
            {
                return this["Key"] as string;
            }
            set
            {
                this["Key"] = value;
            }
        }

        /// <summary>
        /// Gets or sets the size of the key in bits.
        /// </summary>
        /// <value>
        /// The size of the key in bits.
        /// </value>
        [ConfigurationProperty("KeySize", IsRequired = true, DefaultValue = 256)]
        public int KeySize
        {
            get
            {
                return (int)this["KeySize"];
            }
            set
            {
                this["KeySize"] = value;
            }
        }
    }
}
