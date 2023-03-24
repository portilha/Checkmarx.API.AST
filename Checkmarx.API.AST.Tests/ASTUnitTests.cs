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

                astclient.UpdateProjectTags(id, tags);
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
        public void GroupsTest()
        {
            Assert.IsNotNull(astclient);

            astclient.GetGroups();
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

            astclient.Projects.UpdateProjectAsync(new Guid("ee9feb1b-78b7-4a44-b007-8b8eca3e32b8"), input).Wait();
        }

        [TestMethod]
        public void ListScansTest()
        {
            Assert.IsNotNull(astclient.Scans);

            var projects = astclient.GetAllProjectsDetails().Projects.ToList();
            var proj = projects.Where(x => x.Name == "EM-AMD/bcait-bcaresearch").FirstOrDefault();

            //var proj = astclient.Projects.GetProjectAsync(new Guid("9d0f8153-6da7-45ae-b471-e9fc335c9ed7")).Result;
            var scansList = astclient.GetScans(new Guid(proj.Id)).ToList();
            //var scansList = astclient.Scans.GetListOfScansAsync(proj.Id).Result;
            var lastSASTScan = astclient.GetLastScan(new Guid(proj.Id), true);

            //var oldScanDetails = astclient.GetScanDetails(new Guid(proj.Id), new Guid(lastSASTScan.Id), DateTime.Now);
            //Trace.WriteLine($"Total: {oldScanDetails.SASTResults.Total} | High: {oldScanDetails.SASTResults.High} | Medium: {oldScanDetails.SASTResults.Medium} | Low: {oldScanDetails.SASTResults.Low} | Info: {oldScanDetails.SASTResults.Info} | ToVerify: {oldScanDetails.SASTResults.ToVerify}");


            var newScanDetails = astclient.GetScanDetails(new Guid(proj.Id), new Guid(lastSASTScan.Id));
            Trace.WriteLine($"Total: {newScanDetails.SASTResults.Total} | High: {newScanDetails.SASTResults.High} | Medium: {newScanDetails.SASTResults.Medium} | Low: {newScanDetails.SASTResults.Low} | Info: {newScanDetails.SASTResults.Info} | ToVerify: {newScanDetails.SASTResults.ToVerify}");
        }

        [TestMethod]
        public void ListKicksScansTest()
        {
            Assert.IsNotNull(astclient.Scans);

            var proj = astclient.Projects.GetProjectAsync(new Guid("049b1439-34b1-498b-bae1-c767652fcbc0")).Result;
            //var scansList = astclient.Scans.GetListOfScansAsync(proj.Id).Result;
            var lastSASTScan = astclient.GetLastScan(new Guid(proj.Id), true);
            //var lastKicksScan = astclient.GetLastKicsScan(new Guid(proj.Id), true);

            var scanDetails = astclient.GetScanDetails(new Guid(proj.Id), new Guid(lastSASTScan.Id));
        }

        [TestMethod]
        public void ListScansRefactoringTest()
        {
            Assert.IsNotNull(astclient.Scans);

            //var oldScanDetails = astclient.GetScanDetails(new Guid("f8a2b16b-0044-440b-85ed-474bd5d93fca"), new Guid("5963b856-d815-4b8d-990c-1f1eda9e01fe"), DateTime.Now);
            var newScanDetails = astclient.GetScanDetails(new Guid("f8a2b16b-0044-440b-85ed-474bd5d93fca"), new Guid("5963b856-d815-4b8d-990c-1f1eda9e01fe"));
            
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
            var teste = astclient.GetScanDetails(new Guid("f8a2b16b-0044-440b-85ed-474bd5d93fca"), new Guid("154fe347-d237-49e4-80af-77dfd37fdc9c"));
        }

        [TestMethod]
        public void ScanInfoTest2()
        {
            // SCA scan failed
            var teste = astclient.GetScanDetails(new Guid("f8a2b16b-0044-440b-85ed-474bd5d93fca"), new Guid("154fe347-d237-49e4-80af-77dfd37fdc9c"));
        }

        [TestMethod]
        public void ScanMetadataTest()
        {
            var teste = astclient.SASTMetadata.GetMetadataAsync(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e")).Result;
        }

        [TestMethod]
        public void ScanMetricsTest()
        {
            var teste = astclient.SASTMetadata.MetricsAsync(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e")).Result;
        }

        [TestMethod]
        public void FullMetadataTest()
        {
            List<Tuple<Guid, Guid, string, int?, string>> result = new List<Tuple<Guid, Guid, string, int?, string>>();

            var projectList = astclient.Projects.GetListOfProjectsAsync().Result;
            foreach(var project in projectList.Projects)
            {
                var scan = astclient.GetLastScan(new Guid(project.Id));
                if(scan == null)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), Guid.Empty, project.Name, 0, "No completed scans found"));
                    continue;
                }

                try
                {
                    var scanMetadata = astclient.SASTMetadata.GetMetadataAsync(new Guid(scan.Id)).Result;
                }
                catch (ApiException apiEx)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, apiEx.StatusCode, apiEx.Message));
                }
                catch (Exception ex)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, 0, ex.Message));
                }
            }
            
            foreach(var item in result)
            {
                Console.WriteLine($"Project Id: {item.Item1} | Scan Id: {item.Item2} | Project Name: {item.Item3} | Status Code: {item.Item4} | Message: {item.Item5}");
            }
        }

        [TestMethod]
        public void FullScanDetailsTest()
        {
            List<Tuple<Guid, Guid, string, int?, string>> result = new List<Tuple<Guid, Guid, string, int?, string>>();

            var projectList = astclient.Projects.GetListOfProjectsAsync().Result;
            foreach (var project in projectList.Projects)
            {
                var scan = astclient.GetLastScan(new Guid(project.Id));
                if (scan == null)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), Guid.Empty, project.Name, 0, "No completed scans found"));
                    continue;
                }

                try
                {
                    var scanDetails = astclient.GetScanDetails(new Guid(project.Id), new Guid(scan.Id));
                    if(!string.IsNullOrEmpty(scanDetails.ErrorMessage))
                        result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, 0, scanDetails.ErrorMessage));
                }
                catch (ApiException apiEx)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, apiEx.StatusCode, apiEx.Message));
                }
                catch (Exception ex)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, 0, ex.Message));
                }
            }

            foreach (var item in result)
            {
                Console.WriteLine($"Project Id: {item.Item1} | Scan Id: {item.Item2} | Project Name: {item.Item3} | Status Code: {item.Item4} | Message: {item.Item5}");
            }
        }

        [TestMethod]
        public void SASTResultsTest()
        {
            var teste = astclient.SASTResults.GetSASTResultsByScanAsync(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e")).Result;
        }
    }
}
