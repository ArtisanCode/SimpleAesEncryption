using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Castle.Windsor;
using Castle.MicroKernel.Registration;
using ArtisanCode.SimpleAesEncryption;

namespace ArtisanCode.SimpleAes.CastleWithCustomConfigSection
{
    public class SampleCastleInstaller : IWindsorInstaller
    {
        public void Install(IWindsorContainer container, Castle.MicroKernel.SubSystems.Configuration.IConfigurationStore store)
        {
            container.Register(
                Component.For<IMessageEncryptor>()
                .ImplementedBy<RijndaelMessageEncryptor>()
                .DependsOn(Dependency.OnValue("configurationSectionName", "CustomSimpleAESConfigurationSectionName"))); // use custom config section

            container.Register(
                Component.For<IMessageDecryptor>()
                .ImplementedBy<RijndaelMessageDecryptor>()
                .DependsOn(Dependency.OnValue("configurationSectionName", "CustomSimpleAESConfigurationSectionName"))); // use custom config section

            container.Register(Component.For<IExecuteSample>().ImplementedBy<EncryptionSampleManager>());
        }
    }
}
