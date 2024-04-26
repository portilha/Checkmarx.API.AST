using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTResultsPredicates;
using Checkmarx.API.AST.Services.Scans;
using GraphQL;
using GraphQL.Client.Http;
using GraphQL.Client.Serializer.Newtonsoft;
using Keycloak.Net.Models.Root;
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
using System.Net.Http.Headers;

namespace Checkmarx.API.AST.Tests
{
    public class VulnerabilityModelFilterInput
    {
        // Define properties corresponding to the fields in the filter
        // Example:
        public string Severity { get; set; }
    }

    public class VulnerabilitiesSort
    {
        public string Score { get; set; }
    }

    public class VulnerabilityRisksByScanId
    {
        public int TotalCount { get; set; }
        public RiskLevelCounts UndisclosedRiskLevelCounts { get; set; }
        public List<VulnerabilityItem> Items { get; set; }
    }

    public class RiskLevelCounts
    {
        public int Empty { get; set; }
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int None { get; set; }
    }

    public class VulnerabilityItem
    {
        public PackageState PackageState { get; set; }
        public string Credit { get; set; }
        // Continue defining properties as per your GraphQL response
        public string Cve { get; set; }
        public string Cwe { get; set; }
        // More properties...
    }

    public class PackageState
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }

    public class QueryVariables
    {
        public VulnerabilityModelFilterInput Where { get; set; }
        public int Take { get; set; }
        public int Skip { get; set; }
        public List<VulnerabilitiesSort> Order { get; set; }
        public Guid ScanId { get; set; }
        public bool IsExploitablePathEnabled { get; set; }
    }



    [TestClass]
    public class SCAGraphQLTests
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
        public void PrintBearToken()
        {
            Trace.WriteLine(astclient.authenticate());
        }


        [TestMethod]
        public void ResultsMarkingTest()
        {
            var graphQLClient = new GraphQLHttpClient(
                "https://eu.ast.checkmarx.net/api/sca/graphql/graphql", 
                new NewtonsoftJsonSerializer());

            graphQLClient.HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", astclient.authenticate());


            var request = new GraphQLRequest
            {
                Query = @"
    query ($where: VulnerabilityModelFilterInput, $take: Int!, $skip: Int!, $order: [VulnerabilitiesSort!], $scanId: UUID!, $isExploitablePathEnabled: Boolean!) { 
        vulnerabilitiesRisksByScanId (where: $where, take: $take, skip: $skip, order: $order, scanId: $scanId, isExploitablePathEnabled: $isExploitablePathEnabled) { 
            totalCount, 
            undisclosedRiskLevelCounts { 
                empty, critical, high, medium, low, none 
            }, 
            items { 
                packageState { type, value }, 
                credit, 
                pendingChanges, 
                pendingState, 
                state, 
                isIgnored, 
                cve, 
                cwe, 
                description, 
                packageId, 
                severity, 
                type, 
                published, 
                score, 
                violatedPolicies, 
                isExploitable, 
                isKevDataExists, 
                isExploitDbDataExists, 
                relation, 
                epssData { cve, date, epss, percentile }, 
                isEpssDataExists, 
                detectionDate, 
                isVulnerabilityNew, 
                cweInfo { title }, 
                packageInfo { name, packageRepository, version }, 
                exploitablePath { 
                    methodMatch { fullName, line, namespace, shortName, sourceFile }, 
                    methodSourceCall { fullName, line, namespace, shortName, sourceFile } 
                }, 
                vulnerablePackagePath { id, isDevelopment, isResolved, name, version, vulnerabilityRiskLevel }, 
                references { comment, type, url }, 
                cvss2 { 
                    attackComplexity, 
                    attackVector, 
                    authentication, 
                    availability, 
                    availabilityRequirement, 
                    baseScore, 
                    collateralDamagePotential, 
                    confidentiality, 
                    confidentialityRequirement, 
                    exploitCodeMaturity, 
                    integrityImpact, 
                    integrityRequirement, 
                    remediationLevel, 
                    reportConfidence, 
                    targetDistribution 
                }, 
                cvss3 { 
                    attackComplexity, 
                    attackVector, 
                    availability, 
                    availabilityRequirement, 
                    baseScore, 
                    confidentiality, 
                    confidentialityRequirement, 
                    exploitCodeMaturity, 
                    integrity, 
                    integrityRequirement, 
                    privilegesRequired, 
                    remediationLevel, 
                    reportConfidence, 
                    scope, 
                    userInteraction 
                } 
            } 
        } 
    }",
                Variables = new QueryVariables
                {
                    Where = null,  // Assuming no filter criteria specified
                    Take = 10,
                    Skip = 0,
                    Order = new List<VulnerabilitiesSort> { new VulnerabilitiesSort { Score = "DESC" } },
                    ScanId = Guid.Parse("b8e95032-9e25-428c-b177-25dd56a9855c"),
                    IsExploitablePathEnabled = true
                }
            };

            var response = graphQLClient.SendQueryAsync<VulnerabilityRisksByScanId>(request).Result;


            Assert.IsNotNull(response.Data.Items);


        }
    }

    public class DataResponseType
    {
        public dynamic Results { get; set; }
    }
}
