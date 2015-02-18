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

        [TestMethod]
        public void DecryptMessage_ValidSingleLineLogMessage_DecryptedSucessfully()
        {
            string logMessage = "2014-05-21 21:31:10,381 [10] FATAL MessageEncryptorExample [(null)] - 5njRbMIJh57yuCkLLBES4g==??Pxq+S3xzyNi9gi1GqpQLpg==";

            string result = _target.DecyptMessage(logMessage);

            Assert.AreNotEqual(logMessage, result);
            Assert.IsTrue(result.Contains("Fatal message 1"));
        }

        [TestMethod]
        public void DecryptMessage_ValidMultiLineLogMessage_DecryptedSucessfully()
        {
            string logMessage = @"2014-05-21 21:31:10,383 [10] FATAL MessageEncryptorExample [(null)] - 60hSSiApq0s8Jf4Qo/lYOvCMMXzVwX9NzvZCinWEhN4=??907wl9xaHUWmIdl6pCDbsA==
iGYN8z6B06FIxZwYkJ5NgbAow9wxLH0nh/CITvmi3s4j6KKWl7mkrSI11lkgy+aQbtUEDDYL4OzLKAZvSjsffpdZQ6S0Z9Et1uvnD2l5OU698xcPcXBWbeROZ+20OwGM8paywcFfFA51kymjSsdGgYD+aM33/KuFztAEScoFDyTo6QPJQ/GJmQ0dlw14yri1d0twpIq6y7ht3YYrub/Q2Q==??W62CTZ2n33vaqNcNncwL/A==";

            string result = _target.DecyptMessage(logMessage);

            Assert.AreNotEqual(logMessage, result);
            Assert.IsTrue(result.Contains("Fatal Exception message"));
            Assert.IsTrue(result.Contains("Out of memory inner exception"));
        }

        [TestMethod]
        public void DecryptMessage_EmptyLogMessageString_EmptyStringReturned()
        {
            string result = _target.DecyptMessage(string.Empty);

            Assert.AreEqual(string.Empty, result);
        }

        [TestMethod]
        public void DecryptMessage_NullLogMessageString_EmptyStringReturned()
        {
            string result = _target.DecyptMessage(null);

            Assert.AreEqual(string.Empty, result);
        }

        [TestMethod]
        public void DecryptMessage_InputStringWithMultipleSeperatorCharacters_CorrectResultReturned()
        {

            var encryptor = new RijndaelMessageEncryptor(testConfig);
            var secretMessage = "My ultra secret message";
            var expectedMessageLogInfo = string.Format("{0} ??[3] Level??Warn ", DateTime.Now.ToLongTimeString());
            string input = string.Format("{0}{1}", expectedMessageLogInfo, encryptor.Encrypt(secretMessage));

            var result = _target.DecyptMessage(input);

            Assert.IsNotNull(result);
            Assert.AreEqual(expectedMessageLogInfo + secretMessage, result);
        }
    }
}
