using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services.Reports;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
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
        public void UpdateTagTests()
        {
            UpdateProjectStatus(new Guid("ee9feb1b-78b7-4a44-b007-8b8eca3e32b8"), "pipeline");
            //astclient.UpdateProjectTags("ee9feb1b-78b7-4a44-b007-8b8eca3e32b8", new Dictionary<string, string>() { { "asa_status", "pipeline" } });
        }

        public void UpdateProjectStatus(Guid id, string tag)
        {
            var proj = astclient.Projects.GetProjectAsync(id).Result;
            if (proj != null)
            {
                var tags = proj.Tags;
                if (tags.ContainsKey("asa_status"))
                    tags["asa_status"] = tag;
                else
                    tags.Add("asa_status", tag);

                astclient.UpdateProjectTags(id.ToString(), tags);
            }
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
        public void UpdateTags()
        {
            Assert.IsNotNull(astclient.Projects);

            var proj = astclient.Projects.GetProjectAsync(new Guid("ee9feb1b-78b7-4a44-b007-8b8eca3e32b8")).Result;

            var currentTags = proj.Tags;
            if (currentTags.ContainsKey("asa_status"))
            {
                currentTags["asa_status"] = "Pipeline";
            }

            Services.Projects.ProjectInput input = new Services.Projects.ProjectInput();
            input.Tags = currentTags;

            astclient.Projects.UpdateProjectAsync("ee9feb1b-78b7-4a44-b007-8b8eca3e32b8", input).Wait();
        }

        [TestMethod]
        public void ListScansTest()
        {
            Assert.IsNotNull(astclient.Scans);

            //var scansList = astclient.Scans.GetListOfScansAsync().Result;
            var proj = astclient.Projects.GetProjectAsync(new Guid("a1705d81-091c-4ae5-b5d4-78917e0a4eb0")).Result;
            var scansList = astclient.Scans.GetListOfScansAsync(proj.Id).Result;
            var lastScan = scansList.Scans?.ToList().OrderByDescending(x => x.CreatedAt)?.FirstOrDefault();
            var scanResult = astclient.SASTResults.GetSASTResultsByScanAsync(lastScan.Id).Result;

            //var report = astclient.GetAstScanJsonReport("a1705d81-091c-4ae5-b5d4-78917e0a4eb0", lastScan.Id);
            //var metadata = astclient.SASTMetadata.GetMetadataAsync(new Guid(lastScan.Id)).Result;

            //ASTClient.GEtScanResults()


            foreach (var item in scansList.Scans)
            {
                Trace.WriteLine(item.Id + " " + item.ProjectId);
            }
        }

        [TestMethod]
        public void BranchesTest()
        {
            Guid projectId = new Guid("e85542eb-ee28-45ce-890f-f0a86999c489");

            Assert.IsNotNull(astclient.Projects);
            Assert.IsNotNull(astclient.Projects.GetProjectAsync(projectId).Result);


            var branchesV2 = astclient.GetProjectBranches(projectId).ToList();

            foreach (var item in branchesV2)
                Trace.WriteLine(item);

            Assert.IsNotNull(branchesV2);
            Assert.IsTrue(branchesV2.Count > 0);
        }

        [TestMethod]
        public void ScanInfoTest()
        {
            var teste = astclient.GetScanDetails(new Guid("453f8caf-c9f1-4359-8c58-4d5d3f8b28d8"), new Guid("cce501a8-2060-47c6-9a44-16e5822be301"), DateTime.Now);
        }

        [TestMethod]
        public void ScanInfo2Test()
        {
            var teste = astclient.SASTMetadata.GetMetadataAsync(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e")).Result;
        }
    }
}
