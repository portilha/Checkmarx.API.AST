using Keycloak.Net.Models.Groups;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Checkmarx.API.AST.Tests
{
    [Microsoft.VisualStudio.TestTools.UnitTesting.TestClass]
    public class IAMTests
    {
        private static Keycloak.Net.KeycloakClient keycloakClient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<IAMTests>();

            Configuration = builder.Build();

            keycloakClient = new Keycloak.Net.KeycloakClient(
                Configuration["AcessControlServer"], 
                Configuration["Secret"]);
        }


        [TestMethod]
        public void GetRealmsTest()
        {
            // keycloakClient.GetRealmsAsync("")
        }


        [TestMethod]
        public void AccessTest()
        {
            foreach (var item in keycloakClient.GetGroupHierarchyAsync(Configuration["Tenant"]).Result)
            {
                Trace.WriteLine(item.Name);
            }
        }

        


    }
}
