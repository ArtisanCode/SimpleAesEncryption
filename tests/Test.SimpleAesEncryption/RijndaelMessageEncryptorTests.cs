using ArtisanCode.SimpleAesEncryption;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ArtisanCode.Test.Log4NetMessageEncryptor.Encryption
{
    [TestClass]
    public class RijndaelMessageEncryptorTests
    {
        public RijndaelMessageEncryptor _target;

        public SimpleAesEncryptionConfiguration testConfig;

        [TestInitialize]
        public void __init()
        {
            testConfig = new SimpleAesEncryptionConfiguration();
            testConfig.EncryptionKey = new EncryptionKeyConfigurationElement(256, "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=");

            _target = new RijndaelMessageEncryptor(testConfig);
        }

        [TestMethod]
        public void ConstructorWithConfig_ConfigStoredInCorrectProperty_ConfigCanBeAccessed()
        {
            var localTestConfig = new SimpleAesEncryptionConfiguration();
            localTestConfig.EncryptionKey = new EncryptionKeyConfigurationElement(256, "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=");

            var target = new RijndaelMessageEncryptor(localTestConfig);

            Assert.AreSame(localTestConfig, target.Configuration);
        }


        [TestMethod]
        public void ParameterlessConstructor_ConfigRetrievedFromConfigFile_ConfigCanBeAccessed()
        {
            var target = new RijndaelMessageEncryptor();

            Assert.IsNotNull(target.Configuration);
            Assert.AreEqual("TestKey", target.Configuration.EncryptionKey.Key); // NB: retrieved from the App.config file
        }

        [TestMethod]
        public void Encrypt_EmptyPlaintext_EmptyStringReturned()
        {
            var result = _target.Encrypt("");

            Assert.AreEqual(string.Empty, result);
        }

        [TestMethod]
        public void Encrypt_MessageEncryptedSucessfully_NoExceptionsRaised()
        {
            var result = _target.Encrypt("my very secret string");
        }

        [TestMethod]
        public void Encrypt_NullPlaintext_EmptyStringReturned()
        {
            var result = _target.Encrypt(null);

            Assert.AreEqual(string.Empty, result);
        }

        [TestMethod]
        public void Encrypt_WhitespacePlaintext_PlaintextEncrypted()
        {
            var result = _target.Encrypt("  \t");

            Assert.AreNotEqual(string.Empty, result);
        }
    }
}