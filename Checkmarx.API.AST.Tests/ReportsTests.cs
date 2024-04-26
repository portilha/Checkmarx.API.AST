using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Tests
{
    [Microsoft.VisualStudio.TestTools.UnitTesting.TestClass]
    public class ReportsTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ReportsTests>();

            Configuration = builder.Build();

            if (!string.IsNullOrWhiteSpace(Configuration["API_KEY"]))
            {
                astclient = new ASTClient(
                new System.Uri(Configuration["ASTServer"]),
                new System.Uri(Configuration["AccessControlServer"]),
                Configuration["Tenant"],
                Configuration["API_KEY"]);
            }
            else
            {
                astclient = new ASTClient(
                new System.Uri(Configuration["ASTServer"]),
                new System.Uri(Configuration["AccessControlServer"]),
                Configuration["Tenant"],
                Configuration["ClientId"],
                Configuration["ClientSecret"]);
            }

        }



        [TestMethod]
        public void GetReportTest()
        {
            var findings = astclient.GetCxOneScanJsonReport(
                new Guid("4acd0906-9b7e-4596-9215-0ffe0cf78b1c"), 
                new Guid("b8e95032-9e25-428c-b177-25dd56a9855c"),
                1);

            Assert.IsNotNull(findings);

            Trace.WriteLine("Packages Count: " + findings.ScanResults.Sca.PackagesCount);
            Trace.WriteLine("Vulnerabilities Total: " + findings.ScanResults.Sca.Vulnerabilities.Total);

            foreach (var scaVulnerablePackage in findings.ScanResults.Sca.Packages.Where(X => X.Vulnerabilities.Any()))
            {

                foreach (var vulnerability in scaVulnerablePackage.Vulnerabilities)
                {
                    Trace.WriteLine(vulnerability.SimilarityId + " " + vulnerability.State);
                }

            }

            // astclient.MarkSCAResult(new Guid())
        }

    }
}
