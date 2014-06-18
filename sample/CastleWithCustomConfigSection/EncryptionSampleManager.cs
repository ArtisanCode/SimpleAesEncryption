using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ArtisanCode.SimpleAesEncryption;

namespace ArtisanCode.SimpleAes.CastleWithCustomConfigSection
{
    public class EncryptionSampleManager: IExecuteSample
    {
        public IMessageEncryptor Encryptor { get; set; }
        public IMessageDecryptor Decryptor { get; set; }

        public void ExecuteSample(string input)
        {
            var cyphertext = Encryptor.Encrypt(input);

            var plaintext = Decryptor.Decrypt(cyphertext);

            Console.WriteLine("Input:" + input);
            Console.WriteLine("Cyphertext:" + cyphertext);
            Console.WriteLine("Plaintext:" + plaintext);
        }
    }
}
