Simple Aes Encryption
===================

This library lets you encrypt string based messages using the standard AES symmetric key encryption algorithm (Rijndael). 


Installation
------------

The simple AES encryption library can be downloaded and installed from NuGet: 
http://www.nuget.org/packages/Simple.AES/


Configuration
-------------

Once the NuGet package has been installed, all that is required to use the tool is a few configuration changes.


### 1) Add the SimpleAesEncryptionConfiguration configuration sections

In order to let .NET know that there are some custom configuration settings that can be accessed, you need to update the configSections portion of the configuration file with the following:

```xml
<configsections>
   <section name="MessageEncryption" type="ArtisanCode.SimpleAesEncryption.SimpleAesEncryptionConfiguration, ArtisanCode.SimpleAesEncryption"/>
  <!-- Additional sections may be defined but not duplicated -->
</configsections>
```

### 2) Add encryption configuration

This is the heart of the library, this tells the encryption algorithm everything it needs in order to function correctly.

```xml
<MessageEncryption>
  <EncryptionKey KeySize="256" Key="3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8="/>
</MessageEncryption>
```

**Important**

- The recommended KeySize value is 256 (the maximum permitted). This represents the length in bits of the encryption key. The encryption key must be _exactly_ this length.
- Please **do not use this example key ... EVER**!! Please ensure that you generate a new encryption key in a safe and secure manner. You can find a helper program within the sample folder called KeyGen that is able to create a new symmetric key for the MessageEncryptor. 
The sample key was generated using the following code:
```cs
Convert.ToBase64String(new byte[32] {
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
            });
```
- This key is the same key used to encrypt _and_ decrypt so if this gets compromised then you will need to re-encrypt everything that was encrypted with the compromised key. To help keep this encryption information more secure, it is **_highly recommended_** that you encrypt the `<Log4NetMessageEncryption>...</Log4NetMessageEncryption>` configuration section using a tool like [Aspnet_regiis](http://msdn.microsoft.com/en-US/library/k6h9cz8h(v=vs.100).ASPX)


Usage
-----

There are only two interfaces that this library exposes:

* IMessageEncryptor (https://github.com/ArtisanCode/SimpleAesEncryption/blob/master/src/SimpleAesEncryption/IMessageEncryptor.cs)
* IMessageDecryptor (https://github.com/ArtisanCode/SimpleAesEncryption/blob/master/src/SimpleAesEncryption/IMessageDecryptor.cs)

These interfaces only expose one function each:

```C#
string Encrypt(string source);
```

```C#
string Decrypt(string cypherText);
```

You can create instances of ```RijndaelMessageEncryptor``` and ```RijndaelMessageDecryptor``` directly by using the relevent constructors OR, you can use your favourite Dependency Injection container to manage the instansiation for you.

That's all you need to know in order to start encrypting and decrypting to your heart's content!
