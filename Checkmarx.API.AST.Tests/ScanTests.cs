using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services.Configuration;
using Checkmarx.API.AST.Services.GroupsResult;
using Checkmarx.API.AST.Services.KicsResults;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTQueriesAudit;
using Checkmarx.API.AST.Services.Scans;
using Flurl.Util;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
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
            var project = projects.Single(
                x => x.Name == "plug-and-sell/JAVA/crosssell-core-pb");

            var lastScan = astclient.GetLastScan(project.Id);

            var automatedScanDetails = astclient.GetScanDetails(lastScan.Id);
        }

        [TestMethod]
        public void DeleteProjectsTest()
        {
            var projects = astclient.GetAllProjectsDetails();

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
            var projects = astclient.GetAllProjectsDetails();

            var proj = projects.Where(x => x.Name == "cs_lac_tyt_ws5bfel_util_prod").FirstOrDefault();

            var resultsOverview = astclient.ResultsOverview.ProjectsAsync(new List<Guid>() { proj.Id }).Result;

            var lastSASTScan = astclient.GetLastScan(proj.Id, true, true, scanType: Enums.ScanTypeEnum.sca);

            //var scanners = astclient.GetScanDetailsOLD(new Guid(proj.Id), new Guid(lastSASTScan.Id), DateTime.Now);

            var newScanDetails = astclient.GetScanDetails(lastSASTScan.Id);
        }

        [TestMethod]
        public void GetScanInfoTest()
        {
            var projects = astclient.GetAllProjectsDetails();
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

            var projects = astclient.GetAllProjectsDetails();

            var proj = projects.Single(x => x.Name == "EM-AMD/bcait-bcaresearch");

            var lastSASTScan = astclient.GetLastScan(proj.Id, true);

            var newScanDetails = astclient.GetScanDetails(lastSASTScan.Id);

            Trace.WriteLine($"Total: {newScanDetails.SASTResults.Total} " +
                $"| High: {newScanDetails.SASTResults.High} " +
                $"| Medium: {newScanDetails.SASTResults.Medium} " +
                $"| Low: {newScanDetails.SASTResults.Low} " +
                $"| Info: {newScanDetails.SASTResults.Info} " +
                $"| ToVerify: {newScanDetails.SASTResults.ToVerify}");
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

            var listOfIaCResults = astclient.GetKicsScanResultsById(lastKicsScan.Id);

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
            var proj = astclient.Projects.GetProjectAsync(
                new Guid("80fe1c50-f062-4061-a7ef-576fea9c2971")).Result;

            Scan lastSCAScan = astclient.GetLastScan(proj.Id, true, scanType: Enums.ScanTypeEnum.sca);

            Trace.WriteLine(lastSCAScan.Id);

            Assert.IsNotNull(lastSCAScan);

            var properties = typeof(Services.ScannersResults.ScannerResult).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            var results = astclient.GetScannersResultsById(lastSCAScan.Id, ASTClient.SCA_Engine, ASTClient.SCA_Container_Engine);

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
            }
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
            var scanID = new Guid("24ab41bc-0ac8-43cb-88a9-de2bf8b6303b");

            var lastScan = astclient.Scans.GetScanAsync(scanID).Result;

            string log = astclient.GetScanLog(lastScan.Id, ASTClient.SAST_Engine);

            var duration = (lastScan.UpdatedAt.DateTime - lastScan.CreatedAt.DateTime);

            Trace.WriteLine("Duration of the Total Scan (seconds): " + duration.Minutes + ":" + duration.Seconds);

            var scanProperties = typeof(Scan).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            Trace.WriteLine(string.Join(";", scanProperties.Select(x => "\"" + x.Name + "\"")));


            foreach (var property in scanProperties)
            {
                if (property.Name == "AdditionalProperties")
                    continue;

                Trace.WriteLine($"{property.Name} = {property.GetValue(lastScan)?.ToString()}");
            }

            Trace.WriteLine("Status Details: ");

            foreach (var status in lastScan.StatusDetails)
            {
                foreach (var property in typeof(Services.Scans.StatusDetails).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty))
                {
                    Trace.WriteLine($"\t+ {property.Name} = {property.GetValue(status)?.ToString()}");
                }
            }

            Trace.WriteLine("Metadata: ");

            foreach (var property in typeof(Services.Scans.Metadata).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty))
            {
                if (property.Name == "AdditionalProperties")
                    continue;

                Trace.WriteLine($"\t+ {property.Name} = {property.GetValue(lastScan.Metadata)?.ToString()}");
            }

            Trace.WriteLine("Metadata.Configs: ");

            foreach (var property in lastScan.Metadata.Configs)
            {
                Trace.WriteLine($"\t+ {property.Type} = {property.Value?.Incremental}");
            }

            Trace.WriteLine("---");


            Trace.WriteLine("WorkflowAsync: ");

            var properties = typeof(TaskInfo).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            Trace.WriteLine(string.Join(";", properties.Select(x => $"\"{x.Name}\"")));

            foreach (TaskInfo item in astclient.Scans.WorkflowAsync(scanID).Result)
            {
                foreach (var property in properties)
                {
                    if (property.Name == "AdditionalProperties")
                        continue;

                    Trace.WriteLine($"{property.Name} = {property.GetValue(item)?.ToString()}");
                }

                foreach (var keyValuePair in item.AdditionalProperties)
                {
                    Trace.WriteLine($"\t + {keyValuePair.Key} = {keyValuePair.Value}");
                }

                Trace.WriteLine("---");
            }

            Trace.WriteLine($"Scan Configurations: Project {lastScan.ProjectId} Scan {lastScan.Id}");

            foreach (var scanConfiguration in astclient.GetScanConfigurations(lastScan))
            {
                Trace.WriteLine($"\t + {scanConfiguration.Key}");

                foreach (var property in typeof(ScanParameter).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty))
                {
                    Trace.WriteLine($"\t\t- {property.Name} = {property.GetValue(scanConfiguration.Value)?.ToString()}");
                }
            }

            var teste = astclient.GetScanDetails(lastScan.Id);

            Trace.WriteLine("ScanDetails: ");

            foreach (var property in typeof(ScanDetails).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty))
            {
                Trace.WriteLine($"\t+ {property.Name} = {property.GetValue(teste)?.ToString()}");
            }

            Assert.IsTrue(teste.LoC > 0);
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
                }
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
        public void ListAllSASTScanTimesTest()
        {

            foreach (var project in astclient.GetAllProjectsDetails())
            {
                foreach (var branch in astclient.GetProjectBranches(project.Id))
                {
                    var lastSASTScan = astclient.GetLastScan(project.Id, false, true, branch, Enums.ScanTypeEnum.sast);
                    if (lastSASTScan != null)
                    {
                        var sastStatus = lastSASTScan.StatusDetails.Single(x => x.Name == Enums.ScanTypeEnum.sast.ToString());
                        Trace.WriteLine($"{project.Name} :: {branch} - LoC {sastStatus.Loc}   |   Duration(s) : {sastStatus.Duration.TotalSeconds}");
                    }
                }
            }
        }

        [TestMethod]
        public void SASTResultsTest()
        {
            var teste = astclient.GetSASTScanResultsById(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e"));
        }

        #region ReRun Scans


        [TestMethod]
        public void GetScanLogsTest()
        {
            Trace.WriteLine(astclient.GetScanLog(new Guid("537c5a1c-44c8-41f8-8111-28dbe0dc6a0c"), ASTClient.SAST_Engine));
        }


        [TestMethod]
        public void GetWorkFlowTest()
        {
            Trace.WriteLine("WorkflowAsync: ");

            var properties = typeof(TaskInfo).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            Trace.WriteLine(string.Join(";", properties.Select(x => $"\"{x.Name}\"")));

            foreach (TaskInfo item in astclient.Scans.WorkflowAsync(new Guid("537c5a1c-44c8-41f8-8111-28dbe0dc6a0c")).Result)
            {
                foreach (var property in properties)
                {
                    if (property.Name == "AdditionalProperties")
                        continue;

                    Trace.WriteLine($"{property.Name} = {property.GetValue(item)?.ToString()}");
                }

                foreach (var keyValuePair in item.AdditionalProperties)
                {
                    Trace.WriteLine($"\t + {keyValuePair.Key} = {keyValuePair.Value}");
                }

                Trace.WriteLine("---");
            }
        }

        [TestMethod]
        public void ReRunScanGitTest()
        {
            var gitProj = astclient.Projects.GetProjectAsync(new Guid("4bceceba-3be8-4ef6-b822-c7fee658fbf8")).Result;

            var gitProjLastScan = astclient.GetLastScan(gitProj.Id, true);

            var gitProjScanDetails = astclient.GetScanDetails(gitProjLastScan.Id);

            var gitReScanResult = astclient.ReRunGitScan(gitProj.Id, gitProjScanDetails.RepoUrl, new ConfigType[] { ConfigType.Sast }, "master", "Empty", enableFastScan: true,
                tags: new Dictionary<string, string> { { "Test", null } });

            Trace.WriteLine(gitReScanResult.Id);
        }

        [TestMethod]
        public void ReRunScanZipTest()
        {
            var uploadProj = astclient.Projects.GetProjectAsync(new Guid("4bceceba-3be8-4ef6-b822-c7fee658fbf8")).Result;

            var uploadProjLastScan = astclient.GetLastScan(uploadProj.Id);

            var uploadProjScanDetails = astclient.GetScanDetails(uploadProjLastScan.Id);

            string uploadProjBranch = uploadProjLastScan.Branch;

            var uploadReScanResult = astclient.ReRunUploadScan(uploadProj.Id, uploadProjLastScan.Id, [ConfigType.Sast], uploadProjBranch, uploadProjScanDetails.Preset);
        }

        [TestMethod]
        public void GetFastScanConfigurationValueTest()
        {
            var scan = astclient.Scans.GetScanAsync(new Guid("ed2ad5ac-0aa4-494b-8a95-ef7b27505099")).Result;

            var scanConfigs = astclient.GetScanDetails(scan);

            Assert.IsTrue(scanConfigs.FastConfigurationEnabled);

        }


        [TestMethod]
        public void GetAllScanTriggerByMeTest()
        {
            var search = astclient.SearchScans("cxservice_pedro.portilha@checkmarx.com", "perfomance_test", "ASAProgramTracker");

            Trace.WriteLine(string.Join(";", search.Select(x => x.Id)));

            foreach (var item in search)
            {
                Trace.WriteLine(item.Id + " "+ item.Branch + " " + item.CreatedAt.DateTime.ToString());

                var previousScan = astclient.GetLastScan(item.ProjectId, branch: item.Branch, maxScanDate: item.CreatedAt.DateTime.Add(TimeSpan.FromSeconds(-1)));

                Assert.AreNotEqual(item.Id, previousScan.Id);
            }

            Assert.AreEqual(77, search.Count());
        }


        #endregion
    }
}
