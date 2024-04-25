using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services.GroupsResult;
using Checkmarx.API.AST.Services.KicsResults;
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
using System.Reflection;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ScanTests
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
        public void GetScanDetailsTest()
        {
            var projects = astclient.GetAllProjectsDetails();
            var project = projects.Projects.FirstOrDefault(x => x.Name == "plug-and-sell/JAVA/crosssell-core-pb");

            var lastScan = astclient.GetLastScan(project.Id);

            var automatedScanDetails = astclient.GetScanDetails(lastScan.Id);
        }

        [TestMethod]
        public void DeleteProjectsTest()
        {
            var projects = astclient.GetAllProjectsDetails().Projects.ToList();

            var projsScanned = projects.Where(x => x.Tags.ContainsKey("sast_id"));

            foreach (var project in projsScanned)
            {
                var lastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca);
                if (lastScan != null)
                {
                    var scanDetails = astclient.GetScanDetails(lastScan.Id);
                    var scaResults = scanDetails.ScaResults;
                    if (scaResults != null)
                    {
                        Trace.WriteLine($"Prtoject {project.Name}: Scan Status - {scaResults.Status} | Scan Results - {scaResults.High ?? 0} Highs, {scaResults.Medium ?? 0} Mediums, {scaResults.Low ?? 0} Lows");
                    }
                    else
                    {
                        Trace.WriteLine($"Prtoject {project.Name} has no SCA results.");
                    }
                }
                else
                {
                    Trace.WriteLine($"Prtoject {project.Name} has no scan.");
                }
            }
        }

        [TestMethod]
        public void GetScanConfigurationTest()
        {
            var test = astclient.GetProjectConfiguration(new Guid("0c04039e-69f5-41f7-89f5-2e3fd94bd547"));
        }

        [TestMethod]
        public void GetSCAInfoTest()
        {
            var projects = astclient.GetAllProjectsDetails().Projects.ToList();

            var proj = projects.Where(x => x.Name == "cs_lac_tyt_ws5bfel_util_prod").FirstOrDefault();

            var resultsOverview = astclient.ResultsOverview.ProjectsAsync(new List<Guid>() { proj.Id }).Result;

            var lastSASTScan = astclient.GetLastScan(proj.Id, true, true, scanType: Enums.ScanTypeEnum.sca);

            //var scanners = astclient.GetScanDetailsOLD(new Guid(proj.Id), new Guid(lastSASTScan.Id), DateTime.Now);

            var newScanDetails = astclient.GetScanDetails(lastSASTScan.Id);
        }

        [TestMethod]
        public void GetScanInfoTest()
        {
            var projects = astclient.GetAllProjectsDetails().Projects.ToList();
            //var proj = projects.Where(x => x.Name == "cs_lac_tyt_ws5bfel_util_prod").FirstOrDefault();

            foreach (var proj in projects)
            {
                //var proj = astclient.Projects.GetProjectAsync(new Guid("fd71de0b-b3db-40a8-a885-8c2d0eb481b6")).Result;
                //var scansList = astclient.GetScans(new Guid(proj.Id)).ToList();
                var lastSASTScan = astclient.GetLastScan(proj.Id, true);
                if (lastSASTScan == null)
                    continue;

                var newScanDetails = astclient.GetScanDetails(lastSASTScan.Id);

                if (newScanDetails.SASTResults == null)
                    continue;

                Trace.WriteLine($"Total: {newScanDetails.SASTResults?.Total} | High: {newScanDetails.SASTResults?.High} | Medium: {newScanDetails.SASTResults?.Medium} | Low: {newScanDetails.SASTResults?.Low} | Info: {newScanDetails.SASTResults?.Info} | ToVerify: {newScanDetails.SASTResults?.ToVerify}");
            }
        }

        [TestMethod]
        public void GetScanResultsTest()
        {
            var proj = astclient.Projects.GetProjectAsync(new Guid("723b770a-b9e9-436b-ad66-29326eb6da29")).Result;
            var lastSASTScan = astclient.GetLastScan(proj.Id, true);

            //var newScanDetails = astclient.ScannersResults.GetResultsByScanAsync(new Guid(lastSASTScan.Id)).Result;
            var newScanDetails2 = astclient.GetSASTScanResultsById(lastSASTScan.Id).ToList();
        }

        Guid _projectId = new Guid("6f6579f4-f441-4e8e-8241-f0b4174391d1");

        [TestMethod]
        public void ListScansTest()
        {
            Assert.IsNotNull(astclient.Scans);

            var projects = astclient.GetAllProjectsDetails().Projects.ToList();
            var proj = projects.Where(x => x.Name == "EM-AMD/bcait-bcaresearch").FirstOrDefault();

            //var proj = astclient.Projects.GetProjectAsync(new Guid("9d0f8153-6da7-45ae-b471-e9fc335c9ed7")).Result;
            var scansList = astclient.GetScans(proj.Id).ToList();
            //var scansList = astclient.Scans.GetListOfScansAsync(proj.Id).Result;
            var lastSASTScan = astclient.GetLastScan(proj.Id, true);

            //var oldScanDetails = astclient.GetScanDetails(new Guid(proj.Id), new Guid(lastSASTScan.Id), DateTime.Now);
            //Trace.WriteLine($"Total: {oldScanDetails.SASTResults.Total} | High: {oldScanDetails.SASTResults.High} | Medium: {oldScanDetails.SASTResults.Medium} | Low: {oldScanDetails.SASTResults.Low} | Info: {oldScanDetails.SASTResults.Info} | ToVerify: {oldScanDetails.SASTResults.ToVerify}");


            var newScanDetails = astclient.GetScanDetails(lastSASTScan.Id);
            Trace.WriteLine($"Total: {newScanDetails.SASTResults.Total} | High: {newScanDetails.SASTResults.High} | Medium: {newScanDetails.SASTResults.Medium} | Low: {newScanDetails.SASTResults.Low} | Info: {newScanDetails.SASTResults.Info} | ToVerify: {newScanDetails.SASTResults.ToVerify}");
        }


        [TestMethod]
        public void GetLastScanForKicsTest()
        {
            var proj = astclient.Projects.GetProjectAsync(_projectId).Result;

            Scan lastKicsScan = astclient.GetLastScan(proj.Id, true, scanType: Enums.ScanTypeEnum.kics);

            Assert.AreEqual(lastKicsScan.Id, new Guid("96f11e3b-dd7f-4dcc-8d54-e547e0cd8603"));
        }


        [TestMethod]
        public void ListKicsScanResultsTest()
        {
            var proj = astclient.Projects.GetProjectAsync(_projectId).Result;

            Scan lastKicsScan = astclient.GetLastScan(proj.Id, true, scanType: Enums.ScanTypeEnum.kics);

            Trace.WriteLine(lastKicsScan.Id);

            Assert.AreEqual(lastKicsScan.Id, new Guid("96f11e3b-dd7f-4dcc-8d54-e547e0cd8603"));

            var properties = typeof(Services.KicsResults.KicsResult).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            // Fields
            Trace.WriteLine(string.Join(";", properties.Select(p => "\"" + p.Name +"\"")));

            var listOfIaCResults =  astclient.GetKicsScanResultsById(lastKicsScan.Id);

            Trace.WriteLine(listOfIaCResults.Count());

            //foreach (Services.KicsResults.KicsResult kicsResult in listOfIaCResults)
            //{
            //    foreach (var property in properties)
            //    {
            //        Trace.WriteLine($"{property.Name} = {property.GetValue(kicsResult)?.ToString()}");
            //    }
            //    Trace.WriteLine("---");
            //}
        }

        [TestMethod]
        public void ListSCAScanResultsTest()
        {
            var proj = astclient.Projects.GetProjectAsync(new Guid("80fe1c50-f062-4061-a7ef-576fea9c2971")).Result;

            Scan lastSCAScan = astclient.GetLastScan(proj.Id, true, scanType: Enums.ScanTypeEnum.sca);

            Trace.WriteLine(lastSCAScan.Id);

            Assert.IsNotNull(lastSCAScan);

            var properties = typeof(Services.ScannersResults.ScannerResult).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            var results = astclient.GetScannersResultsById(lastSCAScan.Id, ASTClient.SCA_Engine, ASTClient.SCA_Container_Engine);

            // Assert.AreEqual(results.Count(), 1113);

            foreach (Services.ScannersResults.ScannerResult result in results)
            {
                foreach (var property in properties)
                {
                    Trace.WriteLine($"{property.Name} = {property.GetValue(result)?.ToString()}");
                }

                Trace.WriteLine("- ADDITIONAL --");

                foreach (var property in result.AdditionalProperties)
                {
                    Trace.WriteLine($"\t{property.Key} = {property.Value}");
                }

                Trace.WriteLine("---");

                //if(!types.Contains(result.Type))
                //    types.Add(result.Type);
            }

            //foreach (var type in types) { Trace.WriteLine(type);}
        }

        [TestMethod]
        public void ListSASTScanTest()
        {
            Assert.IsNotNull(astclient);

            var proj = astclient.Projects.GetProjectAsync(new Guid("049b1439-34b1-498b-bae1-c767652fcbc0")).Result;

            var lastSASTScan = astclient.GetLastScan(proj.Id, true, scanType: Enums.ScanTypeEnum.sast);

            Assert.IsNotNull(lastSASTScan);
        }


        [TestMethod]
        public void ListScansRefactoringTest()
        {
            Assert.IsNotNull(astclient.Scans);

            //var oldScanDetails = astclient.GetScanDetails(new Guid("f8a2b16b-0044-440b-85ed-474bd5d93fca"), new Guid("5963b856-d815-4b8d-990c-1f1eda9e01fe"), DateTime.Now);
            var newScanDetails = astclient.GetScanDetails(new Guid("5963b856-d815-4b8d-990c-1f1eda9e01fe"));

        }

        [TestMethod]
        public void ScanInfoTest()
        {
            var teste = astclient.GetScanDetails(new Guid("154fe347-d237-49e4-80af-77dfd37fdc9c"));
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
                var scan = astclient.GetLastScan(project.Id);
                if (scan == null)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(project.Id, Guid.Empty, project.Name, 0, "No completed scans found"));
                    continue;
                }

                try
                {
                    var scanMetadata = astclient.SASTMetadata.GetMetadataAsync(scan.Id).Result;
                }
                //catch (ApiException apiEx)
                //{
                //    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, apiEx.StatusCode, apiEx.Message));
                //}
                catch (Exception ex)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(project.Id, scan.Id, project.Name, 0, ex.Message));
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
                var scan = astclient.GetLastScan(project.Id);
                if (scan == null)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(project.Id, Guid.Empty, project.Name, 0, "No completed scans found"));
                    continue;
                }

                try
                {
                    var scanDetails = astclient.GetScanDetails(scan.Id);
                    if (!string.IsNullOrEmpty(scanDetails.ErrorMessage))
                        result.Add(new Tuple<Guid, Guid, string, int?, string>(project.Id, scan.Id, project.Name, 0, scanDetails.ErrorMessage));
                }
                //catch (ApiException apiEx)
                //{
                //    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, apiEx.StatusCode, apiEx.Message));
                //}
                catch (Exception ex)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(project.Id, scan.Id, project.Name, 0, ex.Message));
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
            var gitProjLastScan = astclient.GetLastScan(gitProj.Id, true);
            var gitProjScanDetails = astclient.GetScanDetails(gitProjLastScan.Id);
            string gitProjbranch = gitProjLastScan.Branch;

            var gitReScanResult = astclient.ReRunGitScan(gitProj.Id, gitProjScanDetails.RepoUrl, new List<ConfigType>() { ConfigType.Sast }, gitProjbranch, gitProjScanDetails.Preset);

            astclient.DeleteScan(gitReScanResult.Id);
        }

        [TestMethod]
        public void ReRunScanZipTest()
        {
            var uploadProj = astclient.Projects.GetProjectAsync(new Guid("604e406d-c186-43ff-8694-ab295c39ea78")).Result;
            var uploadProjLastScan = astclient.GetLastScan(uploadProj.Id, true);
            //var uploadProjLastScan = astclient.Scans.GetScanAsync(new Guid("8f252210-cd6f-4d68-b158-9d7cece265ca")).Result;
            var uploadProjScanDetails = astclient.GetScanDetails(uploadProjLastScan.Id);
            string uploadProjBranch = uploadProjLastScan.Branch;

            var uploadReScanResult = astclient.ReRunUploadScan(uploadProj.Id, uploadProjLastScan.Id, new List<ConfigType>() { ConfigType.Sast }, uploadProjBranch, uploadProjScanDetails.Preset);

            //astclient.DeleteScan(new Guid("fb20eb3c-29aa-461d-ac29-12d238d7e976"));
        }

        public void DownloadSourceCodeTest()
        {
            var uploadProj = astclient.Projects.GetProjectAsync(new Guid("f8a2b16b-0044-440b-85ed-474bd5d93fca")).Result;
            var uploadProjLastScan = astclient.GetLastScan(uploadProj.Id, true);
            var uploadProjScanDetails = astclient.GetScanDetails(uploadProjLastScan.Id);
            string uploadProjBranch = uploadProjLastScan.Branch;

            byte[] source = astclient.Repostore.GetSourceCode(uploadProjLastScan.Id).Result;

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
                    ids.Add(scan.Id);
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
