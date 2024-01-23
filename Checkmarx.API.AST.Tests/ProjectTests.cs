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
using System.Net.Http.Headers;
using System.Net.Http;
using System.Xml.Xsl;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ProjectTests
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
        public void ConnectTest()
        {
            Assert.IsTrue(astclient.Connected);
        }

        [TestMethod]
        public void GetPresetsTest()
        {
            var presets = astclient.GetTenantPresets();
        }

        [TestMethod]
        public void CreateAndScanNewProjectTest()
        {
            try
            {
                //bool createApp = true;
                //string appId = null;

                //if (createApp)
                //{
                //    var apps = astclient.GetAllApplications();
                //    appId = apps.Applications.Where(x => x.Name == "TestApp").FirstOrDefault()?.Id;

                //    if (appId == null)
                //    {
                //        try
                //        {
                //            var newApp = astclient.Applications.CreateApplicationAsync(new ApplicationInput { Name = "TestApp" }).Result;
                //            appId = newApp.Id;
                //        }
                //        catch (Exception ex)
                //        {
                //            Trace.WriteLine(ex.Message);
                //        }
                //    }
                //}

                Dictionary<string, string> tags = new Dictionary<string, string>();
                tags.Add("sast_id", "1111");

                var createdProject = astclient.CreateProject("API Created Project", tags);

                byte[] data = File.ReadAllBytes("D:\\path_to_file\\csharp.zip");

                string branch = null;
                string preset = null;
                string configuration = null;

                astclient.RunUploadScan(new Guid(createdProject.Id), data, new List<ConfigType>() { ConfigType.Sca }, branch, preset, configuration);
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex.Message);
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
        public void GroupsTest()
        {
            Assert.IsNotNull(astclient);

            astclient.GetGroups();
        }

        [TestMethod]
        public void ProjectApplicationTest()
        {
            Assert.IsNotNull(astclient.Applications);

            var projects = astclient.GetAllProjectsDetails();
            var project = projects.Projects.Where(x => x.Name == "hcc/hype-sentry").FirstOrDefault();

            var app = astclient.GetProjectApplication(new Guid(project.Id));
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
        public void BranchesTest()
        {
            Guid projectId = new Guid("155b3c81-5b85-4bdc-9eb2-e69062f6fc7d");

            Assert.IsNotNull(astclient.Projects);
            Assert.IsNotNull(astclient.Projects.GetProjectAsync(projectId).Result);

            var branchesV2 = astclient.GetProjectBranches(projectId).ToList();

            foreach (var item in branchesV2)
                Trace.WriteLine(item);

            Assert.IsNotNull(branchesV2);
            Assert.IsTrue(branchesV2.Count > 0);
        }

        [TestMethod]
        public void SASTResultsTest()
        {
            var teste = astclient.SASTResults.GetSASTResultsByScanAsync(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e")).Result;
        }

        [TestMethod]
        public void GetExclusionsTest()
        {
            Guid projectId = new Guid("155b3c81-5b85-4bdc-9eb2-e69062f6fc7d");

            var test = astclient.GetProjectExclusions(projectId);
        }

        [TestMethod]
        public void SetExclusionsTest()
        {
            Guid projectId = new Guid("155b3c81-5b85-4bdc-9eb2-e69062f6fc7d");

            astclient.SetProjectExclusions(projectId, ".zip,.gz");
        }
    }
}
