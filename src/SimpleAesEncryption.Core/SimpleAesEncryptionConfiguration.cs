using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace ArtisanCode.SimpleAesEncryption
{
    public class SimpleAesEncryptionConfiguration
    {
        public EncryptionKeyConfigurationElement EncryptionKey { get; set; }
        public CipherMode CipherMode { get; set; } = CipherMode.CBC;
        public PaddingMode Padding { get; set; } = PaddingMode.ISO10126;
    }
}
