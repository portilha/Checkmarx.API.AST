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
    public class ProcessTests
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
    }
}
