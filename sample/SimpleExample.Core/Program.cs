using ArtisanCode.SimpleAesEncryption;

var input = "Hello World!";

if (args.Length > 0)
{
    input = args[0];
}

var encryptor = new RijndaelMessageEncryptor("CustomMessageEncryption");
//var encryptor = new RijndaelMessageEncryptor();
var cyphertext = encryptor.Encrypt(input);

var decryptor = new RijndaelMessageDecryptor("CustomMessageEncryption");
//var decryptor = new RijndaelMessageDecryptor();
var plaintext = decryptor.Decrypt(cyphertext);

Console.WriteLine("Input:" + input);
Console.WriteLine("Cyphertext:" + cyphertext);
Console.WriteLine("Plaintext:" + plaintext);

Console.WriteLine();
Console.WriteLine("Please press any key to exit.");
Console.ReadKey();