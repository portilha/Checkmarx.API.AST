using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTResultsPredicates;
using Checkmarx.API.AST.Services.Scans;
using Flurl.Util;
using Keycloak.Net.Models.Root;
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

        [TestMethod]
        public void ListSCAFindings()
        {

            var project = astclient.GetProject(new Guid("80fe1c50-f062-4061-a7ef-576fea9c2971"));

            astclient.GetLastScan(new Guid("80fe1c50-f062-4061-a7ef-576fea9c2971"));

            


        }


        [TestMethod]
        public void ResultsMarkingTest()
        {
            astclient.SCA.UpdateResultState(new Services.PackageInfo
            {
                PackageManager= "Maven", 
                PackageName = "com.thoughtworks.xstream:xstream",
                PackageVersion = "1.4.7",
                VulnerabilityId = "CVE-2021-21344",
                ProjectIds = new Guid[] { new Guid("80fe1c50-f062-4061-a7ef-576fea9c2971") },
                Actions = new[] {
                    new ActionType
                    {
                        Type = "ChangeState",
                        Value = "Confirmed",
                        Comment = "something funny"
                    }
                },
            }).Wait();
        }
    }
}
