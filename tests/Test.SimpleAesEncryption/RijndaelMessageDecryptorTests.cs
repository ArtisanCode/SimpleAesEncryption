using ArtisanCode.SimpleAesEncryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;

namespace ArtisanCode.Test.Log4NetMessageEncryptor.Encryption
{
    [TestClass]
    public class RijndaelMessageDecryptorTests
    {
        public RijndaelMessageDecryptor _target;

        public SimpleAesEncryptionConfiguration testConfig;

        /// <summary>
        /// __inits this instance.
        /// </summary>
        [TestInitialize]
        public void __init()
        {
            testConfig = new SimpleAesEncryptionConfiguration();
            testConfig.EncryptionKey = new EncryptionKeyConfigurationElement(256, "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=");

            _target = new RijndaelMessageDecryptor(testConfig);
        }

        [TestMethod]
        public void ConstructorWithConfig_ConfigStoredInCorrectProperty_ConfigCanBeAccessed()
        {
            var localTestConfig = new SimpleAesEncryptionConfiguration();
            localTestConfig.EncryptionKey = new EncryptionKeyConfigurationElement(256, "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=");

            var target = new RijndaelMessageDecryptor(localTestConfig);

            Assert.AreSame(localTestConfig, target.Configuration);
        }


        [TestMethod]
        public void ParameterlessConstructor_ConfigRetrievedFromConfigFile_ConfigCanBeAccessed()
        {
            var target = new RijndaelMessageDecryptor();

            Assert.IsNotNull(target.Configuration);
            Assert.AreEqual("TestKey", target.Configuration.EncryptionKey.Key); // NB: retrieved from the App.config file
        }

        [TestMethod]
        public void Decrypt_EmptyPlaintext_EmptyStringReturned()
        {
            var result = _target.Decrypt("");

            Assert.AreEqual(string.Empty, result);
        }

        [TestMethod]
        public void Decrypt_EncodedMessageDecrypted_InputMessageEqualsDecryptedOutput()
        {
            var encryptor = new RijndaelMessageEncryptor(testConfig);
            var secretMessage = "My ultra secret message";
            var input = encryptor.Encrypt(secretMessage);

            var result = _target.Decrypt(input);

            Assert.IsNotNull(result);
            Assert.AreEqual(secretMessage, result);
        }

        [TestMethod]
        public void Decrypt_NullPlaintext_EmptyStringReturned()
        {
            var result = _target.Decrypt(null);

            Assert.AreEqual(string.Empty, result);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Decrypt_InvalidLengthTextSentForDecryption_ExceptionThrown()
        {
            var result = _target.Decrypt("dGVzdCBkYXRh??wLQO0465tJ5lxuodSSlmgg==");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Decrypt_InvalidSourceMissingCypherText_ExceptionThrown()
        {
            var result = _target.Decrypt("??wLQO0465tJ5lxuodSSlmgg==");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Decrypt_InvalidSourceMissingSeperator_ExceptionThrown()
        {
            var result = _target.Decrypt("dGVzdCBkYXRhwLQO0465tJ5lxuodSSlmgg====");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Decrypt_InvalidSourceMissingIV_ExceptionThrown()
        {
            var result = _target.Decrypt("dGVzdCBkYXRh??");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptStringFromBytes_EmptyCypherText_ExceptionThrown()
        {
            var result = _target.DecryptStringFromBytes(new byte[0], new byte[] { 0x0, 0x5 });
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptStringFromBytes_NullCypherText_ExceptionThrown()
        {
            var result = _target.DecryptStringFromBytes(null, new byte[] { 0x0, 0x5 });
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptStringFromBytes_EmptyIV_ExceptionThrown()
        {
            var result = _target.DecryptStringFromBytes(new byte[] { 0x0, 0x5 }, new byte[0]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DecryptStringFromBytes_NullIV_ExceptionThrown()
        {
            var result = _target.DecryptStringFromBytes(new byte[] { 0x0, 0x5 }, null);
        }
    }
}
