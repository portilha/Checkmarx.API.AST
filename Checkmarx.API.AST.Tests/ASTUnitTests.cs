
using Checkmarx.API.AST.Services.Reports;
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

            var report = getAstScanJsonReport("a1705d81-091c-4ae5-b5d4-78917e0a4eb0", lastScan.Id);

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

        private static dynamic getAstScanJsonReport(string projectId, string scanId)
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
                    string reportStatus = "requested";
                    string pastReportStatus = reportStatus;
                    //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "Waiting/pooling for AST json report, please wait...");
                    double aprox_seconds_passed = 0.0;
                    while (reportStatus != "completed")
                    {
                        System.Threading.Thread.Sleep(2000);
                        aprox_seconds_passed += 2.020;
                        dynamic statusResponse = astclient.Reports.GetReportAsync(reportId, true);
                        reportId = statusResponse["reportId"].ToObject<string>();
                        reportStatus = statusResponse["status"].ToObject<string>();
                        downloadUrl = statusResponse["url"].ToObject<string>();
                        if (reportStatus != "requested" && reportStatus != "completed" && reportStatus != "started" && reportStatus != "failed")
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
                        if (reportStatus == "failed")
                        {
                            //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "AST API says it could not generate a json report. You may want to [cancel all] and retry with diferent scans.");
                            return null;
                        }
                    }
                    //dynamic scanString = AstApi.downloadScanReportJson(sc, reportId);
                    dynamic scanString = astclient.Reports.DownloadAsync(reportId);
                    return scanString;
                }
                else
                {
                    //Dbug.wline($"Error getting Report of Scan {scanId}");
                }
            }
            
            return null;
        }

    }
}
