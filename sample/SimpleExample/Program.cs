using ArtisanCode.SimpleAesEncryption;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ArtisanCode.SimpleAes.SimpleExample
{
    class Program
    {
        static void Main(string[] args)
        {
            var input = "Hello World!";

            if(args.Length > 0)
            {
                input = args[0];
            }

            var encryptor = new RijndaelMessageEncryptor();
            var cyphertext = encryptor.Encrypt(input);

            var decryptor = new RijndaelMessageDecryptor();
            var plaintext = decryptor.Decrypt(cyphertext);

            Console.WriteLine("Input:" + input);
            Console.WriteLine("Cyphertext:" + cyphertext);
            Console.WriteLine("Plaintext:" + plaintext);

            Console.WriteLine();
            Console.WriteLine("Please press any key to exit.");
            Console.ReadKey();
        }
    }
}
