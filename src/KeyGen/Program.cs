using ArtisanCode.SimpleAesEncryption;
using System;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;

namespace ArtisanCode.SimpleAES.KeyGen.KeyGen
{
    class Program
    {
        static void Main(string[] args)
        {
            int keySize = 256;

            // If the user specified a non default key length
            if(args.Any())
            {
                // If there are missing or additional command-line parameters
                if(args.Length != 2)
                {
                    ExitWithError(1);
                }

                // If the length switch was not selected
                if(!args[0].Equals("-L", StringComparison.OrdinalIgnoreCase))
                {
                    ExitWithError(1);
                }

                // Parse the keySize from the command-line parameters
                // If there was an error, exit
                if (string.IsNullOrWhiteSpace(args[1]) || !Int32.TryParse(args[1], out keySize))
                {
                    ExitWithError(1);
                }
            }

            Console.WriteLine("Generating a new key for Log4Net.MessageEncryptor: ");

            // Read the configuration file for the key size information
            SimpleAesEncryptionConfiguration config = new SimpleAesEncryptionConfiguration() {
                EncryptionKey = new EncryptionKeyConfigurationElement(keySize, "")
            };

            using (RijndaelManaged cryptoContainer = new RijndaelManaged())
            {
                var legalKeys = new [] {128,192,256};
                // Validate KeySize
                if(!legalKeys.Contains(keySize))
                {
                    Console.WriteLine("Invalid Key size (" + keySize + ")");
                    Console.WriteLine("Valid Key sizes are: " + string.Join(", ", legalKeys));

                    return;
                }

                cryptoContainer.KeySize = config.EncryptionKey.KeySize;

                // Generates a new key using the standard .NET method of generating a new symmetric key
                cryptoContainer.GenerateKey();

                var key = Convert.ToBase64String(cryptoContainer.Key);

                // Output the new key to the screen and the clipboard
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine();
                Console.WriteLine(key);
                Console.ResetColor();
            }

            Console.WriteLine();
            Console.WriteLine("Please press any key to exit.");
            Console.ReadKey();
        }

        public static void ExitWithError(int errorCode)
        {
            WriteUsageStatement();
            Environment.Exit(errorCode);
        }

        public static void WriteUsageStatement()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("No Arguments : Use the default key length of 256 bits (recommended)");
            Console.WriteLine("-l or -L : Specifies the key length in 128, 182, or 256)");
        }
    }
}
