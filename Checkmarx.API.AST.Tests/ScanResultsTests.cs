using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTResultsPredicates;
using Checkmarx.API.AST.Services.Scans;
using Flurl.Util;
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
            var projects = astclient.GetAllProjectsDetails();

            var baseProject = projects.Projects.FirstOrDefault(x => x.Name == "test1"); // 6bc29809-094e-4ed4-98e9-d8ef89ea61fe
            var projectWithResultsMarked = projects.Projects.FirstOrDefault(x => x.Name == "test1clone"); // 604e406d-c186-43ff-8694-ab295c39ea78

            var lastScanFromBaseProject = astclient.GetLastScan(new Guid(baseProject.Id));
            var lastScanFromProjectWithResultsMarked = astclient.GetLastScan(new Guid(projectWithResultsMarked.Id));

            var scanResultsMatch = CheckIfTheScanResultsMatchBetween2Scans(astclient, new Guid(lastScanFromBaseProject.Id), astclient, new Guid(lastScanFromProjectWithResultsMarked.Id));

            if(scanResultsMatch)
                MarkScanResultsBasedOnAnotherScan(astclient, new Guid(projectWithResultsMarked.Id), new Guid(lastScanFromProjectWithResultsMarked.Id), astclient, new Guid(baseProject.Id), new Guid(lastScanFromBaseProject.Id));
        }

        private bool CheckIfTheScanResultsMatchBetween2Scans(ASTClient client1, Guid scan1, ASTClient client2, Guid scan2)
        {
            var resultsFromScan1 = client1.GetSASTScanVulnerabilitiesDetails(scan1).ToList();
            var resultsFromScan2 = client2.GetSASTScanVulnerabilitiesDetails(scan2).ToList();

            if (resultsFromScan1.Count() != resultsFromScan2.Count())
                return false;

            foreach (var result in resultsFromScan1)
            {
                if (!resultsFromScan2.Any(x => x.SimilarityID == result.SimilarityID))
                    return false;
            }

            return true;
        }

        private void MarkScanResultsBasedOnAnotherScan(ASTClient baseASTclient, Guid baseProjectId, Guid baseScanId, ASTClient astclientToUpdate, Guid projectToUpdateId, Guid scanToUpdateResultsId)
        {
            var resultsFromScan1 = baseASTclient.GetSASTScanVulnerabilitiesDetails(baseScanId).ToList();
            var resultsFromScan2 = astclientToUpdate.GetSASTScanVulnerabilitiesDetails(scanToUpdateResultsId).ToList();

            List<PredicateBySimiliartyIdBody> body = new List<PredicateBySimiliartyIdBody>();
            foreach (var result in resultsFromScan1)
            {
                var resultToUpdate = resultsFromScan2.Where(x => x.SimilarityID == result.SimilarityID).FirstOrDefault();
                if (resultToUpdate == null)
                {
                    Console.WriteLine($"No result found for SimilarityID {result.SimilarityID}");
                    continue;
                }

                if (resultToUpdate.State == result.State)
                {
                    Console.WriteLine($"No state result changed for SimilarityID {result.SimilarityID}");
                    continue;
                }

                PredicateWithCommentJSON latestPredicate = null;

                var resultPedricate = baseASTclient.SASTResultsPredicates.GetPredicatesBySimilarityIDAsync(result.SimilarityID.ToString()).Result;
                if (resultPedricate.PredicateHistoryPerProject.Any())
                {
                    var projPredicater = resultPedricate.PredicateHistoryPerProject.Where(x => x.ProjectId == baseProjectId.ToString()).FirstOrDefault();
                    if(projPredicater != null)
                    {
                        latestPredicate = projPredicater.Predicates.Where(x => x.State.ToString() == result.State.ToString()).OrderByDescending(x => x.CreatedAt).FirstOrDefault();
                    }
                }

                if (latestPredicate == null)
                {
                    Console.WriteLine($"No results predicate found for SimilarityID {result.SimilarityID}.");
                    continue;
                }

                PredicateBySimiliartyIdBody newBody = new PredicateBySimiliartyIdBody();
                newBody.SimilarityId = latestPredicate.SimilarityId;
                newBody.ProjectId = projectToUpdateId.ToString();
                newBody.Severity = latestPredicate.Severity;
                newBody.State = latestPredicate.State;
                newBody.Comment = latestPredicate.Comment;

                body.Add(newBody);
            }

            if(body.Any())
                astclientToUpdate.SASTResultsPredicates.PredicateBySimiliartyIdAndProjectIdAsync(body).Wait();
            else
                Console.WriteLine($"No result state changes detected between scans.");
        }
    }
}
