using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.Scans;
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
    public class ProjectTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ProjectTests>();

            Configuration = builder.Build();

            astclient = new ASTClient(
                new System.Uri(Configuration["ASTServer"]),
                new System.Uri(Configuration["AccessControlServer"]),
                Configuration["Tenant"],
                Configuration["API_KEY"]);
        }

        [TestMethod]
        public void GetScanConfigurationTest()
        {
            var test = astclient.GetProjectConfiguration(new Guid("0c04039e-69f5-41f7-89f5-2e3fd94bd547"));
        }

        [TestMethod]
        public void GetScanInfoTest()
        {
            var projects = astclient.GetAllProjectsDetails().Projects.ToList();
            //var proj = projects.Where(x => x.Name == "CxAPI-Security/apisec-sast-schema").FirstOrDefault();
            foreach (var proj in projects)
            {
                //var proj = astclient.Projects.GetProjectAsync(new Guid("fd71de0b-b3db-40a8-a885-8c2d0eb481b6")).Result;
                //var scansList = astclient.GetScans(new Guid(proj.Id)).ToList();
                var lastSASTScan = astclient.GetLastScan(new Guid(proj.Id), true);
                if (lastSASTScan == null)
                    continue;

                var newScanDetails = astclient.GetScanDetails(new Guid(proj.Id), new Guid(lastSASTScan.Id));

                if (newScanDetails.SASTResults == null)
                    continue;

                Trace.WriteLine($"Total: {newScanDetails.SASTResults?.Total} | High: {newScanDetails.SASTResults?.High} | Medium: {newScanDetails.SASTResults?.Medium} | Low: {newScanDetails.SASTResults?.Low} | Info: {newScanDetails.SASTResults?.Info} | ToVerify: {newScanDetails.SASTResults?.ToVerify}");
            }
        }

        [TestMethod]
        public void GetScanResultsTest()
        {
            var proj = astclient.Projects.GetProjectAsync(new Guid("f8a2b16b-0044-440b-85ed-474bd5d93fca")).Result;
            var lastSASTScan = astclient.GetLastScan(new Guid(proj.Id), true);

            var newScanDetails = astclient.ScannersResults.GetResultsByScanAsync(new Guid(lastSASTScan.Id)).Result;
            var newScanDetails2 = astclient.GetSASTScanVulnerabilitiesDetails(new Guid(lastSASTScan.Id)).ToList();
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
        public void ScanInfoTest()
        {
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
                    var scanMetadata = astclient.SASTMetadata.GetMetadataAsync(new Guid(scan.Id)).Result;
                }
                //catch (ApiException apiEx)
                //{
                //    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, apiEx.StatusCode, apiEx.Message));
                //}
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
                    if (!string.IsNullOrEmpty(scanDetails.ErrorMessage))
                        result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, 0, scanDetails.ErrorMessage));
                }
                //catch (ApiException apiEx)
                //{
                //    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, apiEx.StatusCode, apiEx.Message));
                //}
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

        #region ReRun Scans

        public void ReRunScanGitTest()
        {
            var gitProj = astclient.Projects.GetProjectAsync(new Guid("fd71de0b-b3db-40a8-a885-8c2d0eb481b6")).Result;
            var gitProjLastScan = astclient.GetLastScan(new Guid(gitProj.Id), true);
            var gitProjScanDetails = astclient.GetScanDetails(new Guid(gitProj.Id), new Guid(gitProjLastScan.Id));
            string gitProjbranch = gitProjLastScan.Branch;

            var gitReScanResult = astclient.ReRunGitScan(new Guid(gitProj.Id), gitProjScanDetails.RepoUrl, gitProjbranch, gitProjScanDetails.Preset);

            astclient.DeleteScan(new Guid(gitReScanResult.Id));
        }

        public void ReRunScanZipTest()
        {
            var uploadProj = astclient.Projects.GetProjectAsync(new Guid("fd71de0b-b3db-40a8-a885-8c2d0eb481b6")).Result;
            var uploadProjLastScan = astclient.GetLastScan(new Guid(uploadProj.Id), true);
            //var uploadProjLastScan = astclient.Scans.GetScanAsync(new Guid("8f252210-cd6f-4d68-b158-9d7cece265ca")).Result;
            var uploadProjScanDetails = astclient.GetScanDetails(new Guid(uploadProj.Id), new Guid(uploadProjLastScan.Id));
            string uploadProjBranch = uploadProjLastScan.Branch;

            var uploadReScanResult = astclient.ReRunUploadScan(new Guid(uploadProj.Id), new Guid(uploadProjLastScan.Id), uploadProjBranch, uploadProjScanDetails.Preset);

            //astclient.DeleteScan(new Guid("fb20eb3c-29aa-461d-ac29-12d238d7e976"));
        }

        public void DownloadSourceCodeTest()
        {
            var uploadProj = astclient.Projects.GetProjectAsync(new Guid("f8a2b16b-0044-440b-85ed-474bd5d93fca")).Result;
            var uploadProjLastScan = astclient.GetLastScan(new Guid(uploadProj.Id), true);
            var uploadProjScanDetails = astclient.GetScanDetails(new Guid(uploadProj.Id), new Guid(uploadProjLastScan.Id));
            string uploadProjBranch = uploadProjLastScan.Branch;

            byte[] source = astclient.Repostore.GetSourceCode(new Guid(uploadProjLastScan.Id)).Result;

            string uploadUrl = astclient.Uploads.GetPresignedURLForUploading().Result;
            astclient.Uploads.SendHTTPRequestByFullURL(uploadUrl, source).Wait();

            //var uploadReScanResult = astclient.ReRunUploadScan(new Guid(uploadProj.Id), uploadProjBranch, uploadProjScanDetails.Preset, uploadUrl);
        }

        public void DeleteScansTest()
        {
            List<Guid> ids = new List<Guid>();

            var prjcts = astclient.GetAllProjectsDetails();
            var projects = prjcts.Projects.ToList();
            foreach (var project in projects)
            {
                var scans = astclient.Scans.GetListOfScansAsync(project.Id).Result;
                //foreach(var scan in scans.Scans.Where(x => x.SourceOrigin == "ASAProgramTracker"))
                foreach (var scan in scans.Scans.Where(x => x.SourceOrigin == "Amazon CloudFront"))
                {
                    ids.Add(new Guid(scan.Id));
                }
            }

            foreach (var id in ids)
            {
                astclient.DeleteScan(id);
            }
        }

        #endregion
    }
}
