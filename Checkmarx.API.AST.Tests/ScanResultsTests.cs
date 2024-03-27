using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTResultsPredicates;
using Checkmarx.API.AST.Services.Scans;
using Flurl.Util;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.VisualStudio.TestTools.UnitTesting.Logging;
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
    public class ScanResultsTests
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
        public void GetScanResultsDetailsTest()
        {
            bool updateState = true;
            bool updateSeverity = true;
            bool updateComment = true;

            var projects = astclient.GetAllProjectsDetails();

            var projectWithResultsMarked = projects.Projects.FirstOrDefault(x => x.Name == "copy");
            var projectToMarkResults = projects.Projects.FirstOrDefault(x => x.Name == "sergioCopy");

            var lastScanFromProjectWithResultsMarked = astclient.GetLastScan(new Guid(projectWithResultsMarked.Id));
            var lastScanFromProjectToMarkResults = astclient.GetLastScan(new Guid(projectToMarkResults.Id));

            var resultsFromScan1 = astclient.GetSASTScanVulnerabilitiesDetails(new Guid(lastScanFromProjectWithResultsMarked.Id)).ToList();
            var resultsFromScan2 = astclient.GetSASTScanVulnerabilitiesDetails(new Guid(lastScanFromProjectToMarkResults.Id)).ToList();

            foreach (var result in resultsFromScan2)
            {
                var baseResult = resultsFromScan1.Where(x => x.SimilarityID == result.SimilarityID && x.QueryID == result.QueryID).FirstOrDefault();

                if (baseResult == null)
                    continue;

                try
                {
                    PredicateHistory predicateHistory = null;
                    var resultPedricate = astclient.SASTResultsPredicates.GetPredicatesBySimilarityIDAsync(result.SimilarityID).Result;
                    if (resultPedricate.PredicateHistoryPerProject.Any())
                    {
                        predicateHistory = resultPedricate.PredicateHistoryPerProject.Where(x => x.ProjectId == projectWithResultsMarked.Id.ToString()).FirstOrDefault();
                        if (predicateHistory == null)
                            continue;

                        List<PredicateBySimiliartyIdBody> body = new List<PredicateBySimiliartyIdBody>();
                        foreach (var predicate in predicateHistory.Predicates.Reverse())
                        {
                            PredicateBySimiliartyIdBody newBody = new PredicateBySimiliartyIdBody();
                            newBody.SimilarityId = predicate.SimilarityId;
                            newBody.ProjectId = projectToMarkResults.Id.ToString();
                            newBody.Severity = updateSeverity ? predicate.Severity : result.Severity;
                            newBody.State = updateState ? predicate.State : result.State;
                            newBody.Comment = updateComment ? predicate.Comment : null;

                            body.Add(newBody);
                        }

                        if (body.Any())
                        {
                            astclient.SASTResultsPredicates.PredicateBySimiliartyIdAndProjectIdAsync(body).Wait();
                        }
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Fail to update result with id {result.ID} because {ex.Message}");
                }
            }
        }


        [TestMethod]
        public void ResultsMarkingTest()
        {
            astclient.MarkResult(new Guid("4bceceba-3be8-4ef6-b822-c7fee658fbf8"), "-25232135", Services.SASTResults.ResultsSeverity.HIGH, Services.SASTResults.ResultsState.NOT_EXPLOITABLE, "Test comment");
        }
    }
}
