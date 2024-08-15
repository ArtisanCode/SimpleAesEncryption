using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace ArtisanCode.SimpleAesEncryption
{

    public abstract class RijndaelMessageHandler
    {
        public const string CYPHER_TEXT_IV_SEPARATOR = "??";

        protected string _configurationSectionPath = "MessageEncryption";

        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageHandler"/> class.
        /// </summary>
        public RijndaelMessageHandler()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

            var configuration = builder.Build();
            var configSection = configuration.GetSection(_configurationSectionPath);
            Configuration = configSection.Get<SimpleAesEncryptionConfiguration>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageHandler"/> class.
        /// </summary>
        public RijndaelMessageHandler(string configurationSectionPath)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

            var configuration = builder.Build();
            var configSection = configuration.GetSection(configurationSectionPath);
            Configuration = configSection.Get<SimpleAesEncryptionConfiguration>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageHandler"/> class.
        /// </summary>
        public RijndaelMessageHandler(IConfiguration configuration)
        {
            var _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            Configuration = _configuration.Get<SimpleAesEncryptionConfiguration>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelMessageHandler"/> class.
        /// </summary>
        public RijndaelMessageHandler(SimpleAesEncryptionConfiguration config)
        {
            Configuration = config ?? throw new ArgumentNullException(nameof(config));
        }

        /// <summary>
        /// Gets or sets the configuration.
        /// </summary>
        public SimpleAesEncryptionConfiguration Configuration { get; }

        /// <summary>
        /// Configures the crypto container.
        /// </summary>
        public virtual void ConfigureCryptoContainer(RijndaelManaged cryptoContainer)
        {
            if (Configuration == null)
            {
                throw new ArgumentNullException(nameof(Configuration), "The whole encryption configuration is null.");
            }

            if (Configuration.EncryptionKey == null)
            {
                throw new ArgumentException(nameof(Configuration), "The encryption key configuration is null.");
            }

            if (string.IsNullOrWhiteSpace(Configuration.EncryptionKey.Key))
            {
                throw new CryptographicException("Encryption key is missing.");
            }

            if (!cryptoContainer.LegalKeySizes.Any(x => (x.MinSize <= Configuration.EncryptionKey.KeySize) && (Configuration.EncryptionKey.KeySize <= x.MaxSize)))
            {
                throw new CryptographicException("Invalid Key Size specified. The recommended value is: 256");
            }

            byte[] key = Convert.FromBase64String(Configuration.EncryptionKey.Key);

            // Check that the key length is equal to config.KeySize / 8
            // e.g. 256/8 == 32 bytes expected for the key
            if (key.Length != (Configuration.EncryptionKey.KeySize / 8))
            {
                throw new CryptographicException("Encryption key is the wrong length. Please ensure that it is *EXACTLY* " + Configuration.EncryptionKey.KeySize + " bits long");
            }

            cryptoContainer.Mode = Configuration.CipherMode;
            cryptoContainer.Padding = Configuration.Padding;
            cryptoContainer.KeySize = Configuration.EncryptionKey.KeySize;
            cryptoContainer.Key = key;

            // Generate a new Unique IV for this container and transaction (can be overridden later to decrypt messages where the IV is known)
            cryptoContainer.GenerateIV();
        }
    }
}
