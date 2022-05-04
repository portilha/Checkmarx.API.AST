
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ASTUnitTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ASTUnitTests>();

            Configuration = builder.Build();

            astclient = new ASTClient(
                new System.Uri(Configuration["ASTServer"]),
                new System.Uri(Configuration["AccessControlServer"]), 
                Configuration["Tenant"], 
                Configuration["API_KEY"]);
        }

        [TestMethod]
        public void ConnectTest()
        {
            Assert.IsTrue(astclient.Connected);
        }

        [TestMethod]
        public void ListProjects()
        {
            Assert.IsNotNull(astclient.Projects);

            var projectsList = astclient.Projects.GetListOfProjectsAsync().Result;

            foreach (var item in projectsList.Projects)
            {
                Trace.WriteLine(item.Id + " " + item.Name + " " + item.RepoUrl);
            }
        }

        [TestMethod]
        public void ListApplications()
        {
            Assert.IsNotNull(astclient.Applications);

            var applicationsList = astclient.Applications.GetListOfApplicationsAsync().Result;

            foreach (var item in applicationsList.Applications)
            {
                Trace.WriteLine(item.Id + " " + item.Name);
            }
        }

        [TestMethod]
        public void ListScansTest()
        {
            Assert.IsNotNull(astclient.Scans);

            //var scansList = astclient.Scans.GetListOfScansAsync().Result;
            var scansList = astclient.Scans.GetListOfScansAsync("a1705d81-091c-4ae5-b5d4-78917e0a4eb0").Result;
            var lastScan = scansList.Scans?.ToList().OrderByDescending(x => x.CreatedAt)?.FirstOrDefault();
            var scanResult = astclient.SASTResults.GetSASTResultsByScanAsync(lastScan.Id).Result;

            foreach (var item in scansList.Scans)
            {
                Trace.WriteLine(item.Id + " " + item.ProjectId);
            }
        }

        // sast results disto -> criar depois no 


        [TestMethod]
        public void GetResultsByScanTest()
        {
            Assert.IsNotNull(astclient.Scans);

            var resultsList = astclient.SASTResults.GetSASTResultsByScanAsync("").Result;
            //loc high mid and lows
        }

        [TestMethod]
        public void GetSASTResultsByScanTest()
        {

        }
    }
}
