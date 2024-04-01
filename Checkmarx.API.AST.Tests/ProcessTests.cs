using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.Applications;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.Scans;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
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


        [TestMethod]
        public void GetQueriesTest()
        {

            foreach (var proj in astclient.GetAllProjectsDetails().Projects)
            {
                Trace.WriteLine($"{proj.Id} - {proj.Name}");
            }



        }


        [TestMethod]
        public void QueriesForProjectTest()
        {

            var listOfQueries = astclient.SASTQuery.GetQueriesForProject(new Guid("ee6c74fb-1b4c-4e70-a29a-531029ed109f")).Where(x => x.IsExecutable).ToDictionary(x => x.Id);

            var ids = "9177140066760164971";

            var properties = typeof(SASTQuery.Query).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (var item in listOfQueries.Values)
            {
                foreach (var property in properties)
                {
                    Trace.WriteLine($"{property.Name} = {property.GetValue(item)?.ToString()}");
                }
                Trace.WriteLine("---");
            }

        }



    }
}
