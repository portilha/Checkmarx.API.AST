using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services.Applications;
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
using System.Text.RegularExpressions;
using System.Xml.Xsl;
using static System.Net.Mime.MediaTypeNames;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class EngineeringTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ProjectTests>();

            Configuration = builder.Build();

            string astServer = Configuration["ASTServer"];
            string accessControl = Configuration["AccessControlServer"];

            astclient = new ASTClient(
                new System.Uri(astServer),
                new System.Uri(accessControl), 
                Configuration["Tenant"], 
                Configuration["API_KEY"]);
        }

        [TestMethod]
        public void QueriesTest()
        {
            // Get query
            var queryFile = "D:\\Users\\bruno.vilela\\OneDrive - Checkmarx\\Documents\\use_of_hardcoded_password.txt";
            string customQuery = File.ReadAllText(queryFile);
            string queryName = Path.GetFileNameWithoutExtension(queryFile);

            var projects = astclient.GetAllProjectsDetails();
            var project = projects.Projects.Where(x => x.Name == "tst_csharp_w_vuln").FirstOrDefault();

            

            // Get scan accuraci and languages
            var scanInfo = GetScanAccuracyAndLanguagesFromScanLog(new Guid("f14b672f-2823-4dbf-b1d0-13830bb15460"));

            if (!scanInfo.Item2.Any())
                throw new Exception($"No query group found to override with the name {queryName}");

            string language = null;
            if (scanInfo.Item2.Any(x => x.ToLower() == "csharp"))
                language = "csharp";
            else if (scanInfo.Item2.Any(x => x.ToLower() == "java"))
                language = "java";
            else if (scanInfo.Item2.Any(x => x.ToLower() == "javascript"))
                language = "javascript";
            else if (scanInfo.Item2.Any(x => x.ToLower() == "python"))
                language = "python";

            // Logic to fetch query to override
            var queries = astclient.GetProjectQueries(new Guid(project.Id)).ToList();
            var possibleQueriesToOverride = queries.Where(x => x.Name.ToLower() == queryName.ToLower());

            //var verificarEsteCaso = queries.Where(x => x.Name == "Client_DOM_XSS");

            Services.SASTQuery.Query queryTOOverride = null;
            if (!string.IsNullOrWhiteSpace(language))
            {
                var langQueries = possibleQueriesToOverride.Where(x => x.Lang.ToLower() == language.ToLower());
                queryTOOverride = langQueries.FirstOrDefault();
            }

            if (queryTOOverride == null)
            {
                foreach (var lang in scanInfo.Item2)
                {
                    queryTOOverride = possibleQueriesToOverride.Where(x => x.Lang.ToLower() == lang.ToLower()).FirstOrDefault();
                    if (queryTOOverride != null)
                        break;
                }
            }

            var searchForAnExistingQuery = astclient.GetProjectQuery(new Guid(project.Id), queryTOOverride.Path, false);
            if(searchForAnExistingQuery.Level == "Project")
            {
                // Error -> Already a query at Project level
            }

            // Insert query
            astclient.SaveProjectQuery(new Guid(project.Id), queryTOOverride.Name, queryTOOverride.Path, customQuery);

            var insertedQuery = astclient.GetProjectQuery(new Guid(project.Id), queryTOOverride.Path, false);

            // Trigger Scan
            var lastScan = astclient.GetLastScan(new Guid(project.Id));
            var branch = lastScan.Branch;
            var preset = "ASA Premium";
            var configuration = "Default";

            var newScan = astclient.ReRunUploadScan(new Guid(project.Id), new Guid(lastScan.Id), branch, preset, configuration);

            bool scanIsRuning = true;
            while (scanIsRuning)
            {
                System.Threading.Thread.Sleep(10 * 1000);

                var createdScan = astclient.Scans.GetScanAsync(new Guid(newScan.Id)).Result;
                if(createdScan.Status == Status.Completed)
                {
                    scanIsRuning = false;
                }
            }

            astclient.DeleteProjectQuery(new Guid(project.Id), insertedQuery.Path);
        }

        private Tuple<double, List<string>> GetScanAccuracyAndLanguagesFromScanLog(Guid scanId)
        {
            var log = astclient.GetSASTScanLog(scanId);

            // Read Log
            double scanAccuracy = 0;
            List<string> scanLanguages = new List<string>();

            Regex regex = new Regex("^Scan\\scoverage:\\s+(?<pc>[\\d\\.]+)\\%", RegexOptions.Multiline);
            MatchCollection mc = regex.Matches(log);
            foreach (Match m in mc)
            {
                GroupCollection groups = m.Groups;
                double.TryParse(groups["pc"].Value.Replace(".", ","), out scanAccuracy);
            }

            //Languages that will be scanned: Java=3, CPP=1, JavaScript=1, Groovy=6, Kotlin=361
            Regex regexLang = new Regex("^Languages\\sthat\\swill\\sbe\\sscanned:\\s+(?:(\\w+)\\=\\d+\\,?\\s?)+", RegexOptions.Multiline);
            MatchCollection mcLang = regexLang.Matches(log);
            var langsTmp = new List<string>();
            foreach (Match m in mcLang)
            {
                System.Text.RegularExpressions.GroupCollection groups = m.Groups;
                foreach (System.Text.RegularExpressions.Group g in groups)
                {
                    foreach (Capture c in g.Captures)
                    {
                        if (c.Value != "" && !c.Value.StartsWith("Languages that will be scanned:"))
                        {
                            langsTmp.Add(c.Value);
                        }
                    }
                }
            }

            if (langsTmp.Count > 0)
            {
                scanLanguages = langsTmp;
            }

            return new Tuple<double, List<string>>(scanAccuracy, scanLanguages);
        }

        private void InsertQuery(Services.SASTQueriesAudit.Queries baseQuery, string query)
        {
            var queryRequest = new Services.SASTQueriesAudit.QueryRequest()
            {
                Name = baseQuery.Name,
                Source = query,
                Path = baseQuery.Path,
                Metadata = new Services.SASTQueriesAudit.Metadata()
                {
                    //Cwe =  baseQuery.Id,
                    Severity = 1,
                    IsExecutable = true,
                    //CxDescriptionID =
                },
            };

            astclient.SASTQueriesAudit.QueriesPOSTAsync(queryRequest).Wait();
        }
    }
}
