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
            var proj = astclient.Projects.GetProjectAsync(id.ToString()).Result;
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

            var proj = astclient.Projects.GetProjectAsync("ee9feb1b-78b7-4a44-b007-8b8eca3e32b8").Result;

            var currentTags = proj.Tags;
            if (currentTags.ContainsKey("status"))
            {
                currentTags["status"] = "Pipeline";
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
            var proj = astclient.Projects.GetProjectAsync("a1705d81-091c-4ae5-b5d4-78917e0a4eb0").Result;
            var scansList = astclient.Scans.GetListOfScansAsync(proj.Id).Result;
            var lastScan = scansList.Scans?.ToList().OrderByDescending(x => x.CreatedAt)?.FirstOrDefault();
            var scanResult = astclient.SASTResults.GetSASTResultsByScanAsync(lastScan.Id).Result;

            var report = getAstScanJsonReport("a1705d81-091c-4ae5-b5d4-78917e0a4eb0", lastScan.Id);
            var metadata = astclient.SASTMetadata.GetMetadataAsync(new Guid(lastScan.Id)).Result;

            //ASTClient.GEtScanResults()


            foreach (var item in scansList.Scans)
            {
                Trace.WriteLine(item.Id + " " + item.ProjectId);
            }
        }

        private static ReportResults getAstScanJsonReport(string projectId, string scanId)
        {
            ScanReportCreateInput sc = new ScanReportCreateInput();
            sc.ReportName = BaseReportCreateInputReportName.ScanReport;
            sc.ReportType = BaseReportCreateInputReportType.Cli;
            sc.FileFormat = BaseReportCreateInputFileFormat.Json;
            sc.Data = new Data { ProjectId = projectId, ScanId = scanId };

            var createReportOutut = astclient.Reports.CreateReportAsync(sc).Result;
            if(createReportOutut != null)
            {
                var createReportId = createReportOutut.ReportId;
                if (createReportId != null)
                {
                    string downloadUrl = null;
                    Guid reportId = createReportId;
                    string reportStatus = "Requested";
                    string pastReportStatus = reportStatus;
                    //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "Waiting/pooling for AST json report, please wait...");
                    double aprox_seconds_passed = 0.0;
                    while (reportStatus != "Completed")
                    {
                        System.Threading.Thread.Sleep(2000);
                        aprox_seconds_passed += 2.020;
                        var statusResponse = astclient.Reports.GetReportAsync(reportId, true).GetAwaiter().GetResult();
                        reportId = statusResponse.ReportId;
                        reportStatus = statusResponse.Status.ToString();
                        downloadUrl = statusResponse.Url;
                        if (reportStatus != "Requested" && reportStatus != "Completed" && reportStatus != "Started" && reportStatus != "Failed")
                        {
                            //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "Abnormal AST json report status! You may want to [cancel all] and retry.");
                        }
                        if (pastReportStatus != reportStatus)
                        {
                            pastReportStatus = reportStatus;
                        }
                        if (aprox_seconds_passed > 15.0 * 60.0)
                        {
                            //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "AST json report is taking a long time! You may want to [cancel all] and retry.");
                        }
                        if (reportStatus == "Failed")
                        {
                            //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "AST API says it could not generate a json report. You may want to [cancel all] and retry with diferent scans.");
                            return null;
                        }
                    }
                    //dynamic scanString = AstApi.downloadScanReportJson(sc, reportId);
                    //dynamic scanString = downloadScanReportJsonUrl(sc, downloadUrl);
                    //astclient.Reports.DownloadAsync(new Guid("ee845fdc-2b14-4b21-9a5e-e636649df64d")).GetAwaiter().GetResult();
                    
                    var reportString = astclient.Reports.DownloadScanReportJsonUrl(downloadUrl).GetAwaiter().GetResult();

                    return JsonConvert.DeserializeObject<ReportResults>(reportString);
                }
                else
                {
                    //Dbug.wline($"Error getting Report of Scan {scanId}");
                }
            }
            
            return null;
        }

        public static dynamic downloadScanReportJsonUrl(ScanReportCreateInput sc, string url)
        {
            //string serverRestEndpoint = $"{sc.Uri}api/reports/{reportId}/download";
            string serverRestEndpoint = url;
            WebRequest request = WebRequest.Create(serverRestEndpoint);
            request.Method = "GET";
            //request.Headers.Add("Authorization", GetAuthToken(sc));
            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream dataStream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                            return JsonConvert.DeserializeObject<dynamic>(responseFromServer);
                        }
                    }
                }
            }
            catch (WebException we)
            {
                //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, we.GetType().Name + " found. StackTrace: " + we.StackTrace);
                if (we.Response != null)
                {
                    using (Stream dataStream = we.Response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                            //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, $"Server response: {responseFromServer}");
                        }
                    }
                }
                throw we;
            }
        }
    }
}
