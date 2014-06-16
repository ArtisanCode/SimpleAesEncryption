using ArtisanCode.SimpleAesEncryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace ArtisanCode.Test.Log4NetMessageEncryptor.Encryption
{
    [TestClass]
    public class RijndaelMessageHandlerTests
    {
        public RijndaelMessageHandlerTestHarness _target;

        public SimpleAesEncryptionConfiguration testConfig;

        [TestInitialize]
        public void __init()
        {
            testConfig = new SimpleAesEncryptionConfiguration();

            _target = new RijndaelMessageHandlerTestHarness(testConfig);
        }


        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void ConfigureCryptoContainer_EmptyEncryptionKey_CryptographicExceptionThrown()
        {
            var testContainer = new RijndaelManaged();
            SimpleAesEncryptionConfiguration invalidTestConfig = new SimpleAesEncryptionConfiguration
            {
                EncryptionKey = new EncryptionKeyConfigurationElement(256, string.Empty),
            };

            _target.ConfigureCryptoContainer(testContainer, invalidTestConfig);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void ConfigureCryptoContainer_IllegalKeySizeTooLarge_CryptographicExceptionThrown()
        {
            var testContainer = new RijndaelManaged();
            SimpleAesEncryptionConfiguration invalidTestConfig = new SimpleAesEncryptionConfiguration
            {
                EncryptionKey = new EncryptionKeyConfigurationElement(257, "testKey"),
            };

            _target.ConfigureCryptoContainer(testContainer, invalidTestConfig);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void ConfigureCryptoContainer_IllegalKeySizeTooSmall_CryptographicExceptionThrown()
        {
            var testContainer = new RijndaelManaged();
            SimpleAesEncryptionConfiguration invalidTestConfig = new SimpleAesEncryptionConfiguration
            {
                EncryptionKey = new EncryptionKeyConfigurationElement(127, "testKey"),
            };

            _target.ConfigureCryptoContainer(testContainer, invalidTestConfig);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void ConfigureCryptoContainer_InvalidKeyLength_CryptographicExceptionThrown()
        {
            var testContainer = new RijndaelManaged();
            SimpleAesEncryptionConfiguration invalidTestConfig = new SimpleAesEncryptionConfiguration
            {
                EncryptionKey = new EncryptionKeyConfigurationElement(255, Convert.ToBase64String(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF })),
            };

            _target.ConfigureCryptoContainer(testContainer, invalidTestConfig);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ConfigureCryptoContainer_NullConfiguration_ArgumentNullExceptionThrown()
        {
            var testContainer = new RijndaelManaged();
            SimpleAesEncryptionConfiguration invalidTestConfig = null;

            _target.ConfigureCryptoContainer(testContainer, invalidTestConfig);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ConfigureCryptoContainer_NullEncryptionKey_CryptographicExceptionThrown()
        {
            var testContainer = new RijndaelManaged();
            SimpleAesEncryptionConfiguration invalidTestConfig = new SimpleAesEncryptionConfiguration
            {
                EncryptionKey = null,
            };

            _target.ConfigureCryptoContainer(testContainer, invalidTestConfig);
        }

        [TestMethod]
        public void ConfigureCryptoContainer_ValidConfiguration_ContainerIsConfigured()
        {
            var testContainer = new RijndaelManaged();
            var testKey = new byte[32] {
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
            };
            var validTestConfig = new SimpleAesEncryptionConfiguration()
            {
                EncryptionKey = new EncryptionKeyConfigurationElement(256, Convert.ToBase64String(testKey)),
                CipherMode = CipherMode.CBC,
                Padding = PaddingMode.ISO10126
            };

            _target.ConfigureCryptoContainer(testContainer, validTestConfig);

            Assert.IsTrue(testKey.SequenceEqual(testContainer.Key));
            Assert.AreEqual(validTestConfig.CipherMode, testContainer.Mode);
            Assert.AreEqual(validTestConfig.Padding, testContainer.Padding);
            Assert.AreEqual(validTestConfig.EncryptionKey.KeySize, testContainer.KeySize);
            Assert.IsTrue(testContainer.IV.Length == 16);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void ConfigureCryptoContainer_WhitespaceEncryptionKey_CryptographicExceptionThrown()
        {
            var testContainer = new RijndaelManaged();
            SimpleAesEncryptionConfiguration invalidTestConfig = new SimpleAesEncryptionConfiguration
            {
                EncryptionKey = new EncryptionKeyConfigurationElement(256, "  \t"),
            };

            _target.ConfigureCryptoContainer(testContainer, invalidTestConfig);
        }

    }

    public class RijndaelMessageHandlerTestHarness : RijndaelMessageHandler
    {
        public RijndaelMessageHandlerTestHarness(SimpleAesEncryptionConfiguration config)
            : base(config)
        {

        }
    }
}
