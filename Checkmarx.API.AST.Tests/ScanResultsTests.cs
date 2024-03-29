using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTResultsPredicates;
using Checkmarx.API.AST.Services.Scans;
using Flurl.Util;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.VisualStudio.TestTools.UnitTesting.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ScanResultsTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ProjectTests>();

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

        Guid projectId = new Guid("4bceceba-3be8-4ef6-b822-c7fee658fbf8");


        [TestMethod]
        public void SASTResultsMarkingTest()
        {
            astclient.MarkSASTResult(projectId, -25232135, Services.SASTResults.ResultsSeverity.HIGH, Services.SASTResults.ResultsState.NOT_EXPLOITABLE, "Test comment");
        
            // assert that the changes were made.

            // Assert.AreEqual(Services.SASTResults.ResultsState.NOT_EXPLOITABLE, astclient.SASTResults)
        }


        [TestMethod]
        public void IaCResultsMarkingTest()
        {
            Assert.IsTrue(astclient.MarkKICSResult(projectId));
        }


        [TestMethod]
        public void SCAResultsMarkingTest()
        {
            Assert.IsTrue(astclient.MarkSCAResult(projectId));
        }


    }
}
