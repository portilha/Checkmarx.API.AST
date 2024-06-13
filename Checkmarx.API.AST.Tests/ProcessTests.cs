using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.Applications;
using Checkmarx.API.AST.Services.PresetManagement;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTQueriesAudit;
using Checkmarx.API.AST.Services.Scans;
using Keycloak.Net.Models.Root;
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
        public void GetPresetDetailsTest()
        {
            var properties = typeof(PresetDetails).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (var item in astclient.GetAllPresetsDetails())
            {
                foreach (var property in properties)
                {
                    Trace.WriteLine($"{property.Name} = {property.GetValue(item)?.ToString()}");
                }

                foreach (var queryId in item.QueryIds)
                {
                    Trace.WriteLine($"\t{queryId}");
                }

                Trace.WriteLine("---");
            }
        }

        [TestMethod]
        public void GetQueriesTest()
        {
            var properties = typeof(Queries).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (var item in astclient.SASTQueriesAudit.QueriesAllAsync().Result)
            {
                foreach (var property in properties)
                {
                    Trace.WriteLine($"{property.Name} = {property.GetValue(item)?.ToString()}");
                }

                Trace.WriteLine("---");
            }
        }

        [TestMethod]
        public void QueriesForProjectTest()
        {
            var listOfQueries = astclient.SASTQuery.GetQueriesForProject(astclient.Projects.GetListOfProjectsAsync().Result.Projects.First().Id);

            Dictionary<string, SASTQuery.Query> keys = new Dictionary<string, SASTQuery.Query>();

            var properties = typeof(SASTQuery.Query).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (var query in listOfQueries)
            {
                if (!keys.ContainsKey(query.Id))
                    keys.Add(query.Id, query);
                else
                {
                    foreach (var property in properties)
                    {
                        Trace.WriteLine($"{property.Name} = {property.GetValue(keys[query.Id])?.ToString()}");
                    }
                    Trace.WriteLine("---");

                    foreach (var property in properties)
                    {
                        Trace.WriteLine($"{property.Name} = {property.GetValue(query)?.ToString()}");
                    }
                    Trace.WriteLine("---");
                    Trace.WriteLine("========================");
                }
            }
        }

        [TestMethod]
        public void LogEngineTest()
        {
            Trace.WriteLine(astclient.GetSASTScanLog(astclient.GetLastScan(astclient.Projects.GetListOfProjectsAsync().Result.Projects.Last().Id).Id));
        }


        [TestMethod]
        public void KicsGetHistoryTest()
        {
            var properties = typeof(Predicate).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (KICSPredicateHistory item in astclient.KicsResultsPredicates.ReadAsync("ed440168d16f631592d46e6511d6db66ea1927402a550aa04c48a3709bf4023d",
                [new Guid("1c724868-72fa-4bfe-aca5-6c9096b48408")]).Result.PredicateHistoryPerProject)
            {
                foreach (Predicate predicate in item.Predicates.Reverse())
                {
                    foreach (var property in properties)
                    {
                        Trace.WriteLine($"{property.Name} = {property.GetValue(predicate)?.ToString()}");
                    }
                    Trace.WriteLine("---");
                }
            }
        }

        [TestMethod]
        public void KicsPostHistoryTest()
        {
            KICSPredicateHistory item = astclient.KicsResultsPredicates.ReadAsync("ed440168d16f631592d46e6511d6db66ea1927402a550aa04c48a3709bf4023d", [new Guid("1c724868-72fa-4bfe-aca5-6c9096b48408")]).Result.PredicateHistoryPerProject.SingleOrDefault();

            var newHistory = item.Predicates.Reverse();
            foreach (var property in newHistory)
            {
                property.SimilarityId = "4816e8d3444a0b6e75ca263b7e6e2f7e867393a03848608efc028a86bd2cde13";

                if (!string.IsNullOrWhiteSpace(property.Comment))
                    property.Comment = $"{property.CreatedBy} added new comment: \"{property.Comment}\"";
            }

            astclient.KicsResultsPredicates.UpdateAsync(newHistory).Wait();
        }


        [TestMethod]
        public void SASTClearResultHistoryTest()
        {
            var historyPerProject = astclient.SASTResultsPredicates.GetPredicatesBySimilarityIDAsync(-717279067).Result.PredicateHistoryPerProject;

            Assert.IsTrue(historyPerProject.Any());

            var singleHistoryPerProject = astclient.SASTResultsPredicates.GetPredicatesBySimilarityIDAsync(-717279067, [new Guid("439ab490-a491-4e81-b36d-fefdb5113e22")]).Result.PredicateHistoryPerProject;

            Assert.IsTrue(singleHistoryPerProject.SingleOrDefault() != null);
        }

    }

}
