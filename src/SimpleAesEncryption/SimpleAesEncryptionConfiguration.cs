using System.Configuration;
using System.Security.Cryptography;

namespace ArtisanCode.SimpleAesEncryption
{
    public class SimpleAesEncryptionConfiguration : ConfigurationSection
    {
        /// <summary>
        /// Gets or sets the cipher mode.
        /// </summary>
        /// <value>
        /// The cipher mode.
        /// </value>
        [ConfigurationProperty("EncryptionKey", IsRequired = true)]
        public EncryptionKeyConfigurationElement EncryptionKey
        {
            get
            {
                return (EncryptionKeyConfigurationElement)this["EncryptionKey"];
            }
            set
            {
                this["EncryptionKey"] = value;
            }
        }

        /// <summary>
        /// Gets or sets the cipher mode.
        /// </summary>
        /// <value>
        /// The cipher mode.
        /// </value>
        [ConfigurationProperty("CipherMode", IsRequired = false, DefaultValue = CipherMode.CBC)]
        public CipherMode CipherMode
        {
            get
            {
                return (CipherMode)this["CipherMode"];
            }
            set
            {
                this["CipherMode"] = value;
            }
        }

        /// <summary>
        /// Gets or sets the padding mode.
        /// </summary>
        /// <value>
        /// The padding mode.
        /// </value>
        [ConfigurationProperty("Padding", IsRequired = false, DefaultValue = PaddingMode.ISO10126)]
        public PaddingMode Padding
        {
            get
            {
                return (PaddingMode)this["Padding"];
            }
            set
            {
                this["Padding"] = value;
            }
        }
    }
}