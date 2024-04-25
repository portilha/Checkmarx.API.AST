using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class FeatureFlagsTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ProjectTests>();

            Configuration = builder.Build();

            string astServer = Configuration["ASTServer"];
            string accessControl = Configuration["AccessControlServer"];

            astclient = new ASTClient(
                new System.Uri(astServer),
                new System.Uri(accessControl),
                Configuration["Tenant"],
                Configuration["API_KEY"]);
        }

        [TestMethod]
        public void ListFeatureFlagsTest()
        {
            foreach (var flag in astclient.FeatureFlags.GetFlagsAsync().Result)
            {
                Trace.WriteLine(flag.Name + " :: " + flag.Status);
            }
        }


    }
}
