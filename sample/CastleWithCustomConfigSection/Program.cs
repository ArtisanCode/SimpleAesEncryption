using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Castle.Windsor;

namespace ArtisanCode.SimpleAes.CastleWithCustomConfigSection
{
    class Program
    {
        static void Main(string[] args)
        {
            var input = "Hello World!";

            if (args.Length > 0)
            {
                input = args[0];
            }

            var Container = new WindsorContainer();

            // Configure Castle
            Container.Install(new SampleCastleInstaller());

            // Resolve sample manager and execute
            var sampleManager = Container.Resolve<IExecuteSample>();
            sampleManager.ExecuteSample(input);
            
            Console.WriteLine();
            Console.WriteLine("Please press any key to exit.");
            Console.ReadKey();
        }
    }
}
