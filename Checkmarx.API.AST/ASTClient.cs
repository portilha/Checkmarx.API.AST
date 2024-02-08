using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Services.Applications;
using Checkmarx.API.AST.Services.Projects;
using Checkmarx.API.AST.Services.Scans;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using Checkmarx.API.AST.Models.Report;
using System.Threading.Tasks;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.KicsResults;
using Checkmarx.API.AST.Services.ScannersResults;
using System.Reflection;
using Checkmarx.API.AST.Services.ResultsSummary;
using System.Security.Cryptography.X509Certificates;
using Checkmarx.API.AST.Services.Configuration;
using Checkmarx.API.AST.Services.Repostore;
using Checkmarx.API.AST.Services.Uploads;
using System.Diagnostics;
using Checkmarx.API.AST.Services.SASTQueriesAudit;
using Checkmarx.API.AST.Services.Logs;
using System.IO;
using System.Net;
using System.Text;
using Checkmarx.API.AST.Services.ResultsOverview;
using Checkmarx.API.AST.Services.PresetManagement;

namespace Checkmarx.API.AST
{
    public class ASTClient
    {
        public Uri AcessControlServer { get; private set; }
        public Uri ASTServer { get; private set; }
        public string Tenant { get; }
        public string KeyApi { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }

        private readonly HttpClient _httpClient = new HttpClient();

        public int _bearerExpiresIn;
        private DateTime _bearerValidTo;

        private Projects _projects;
        public Projects Projects
        {
            get
            {
                if (_projects == null && Connected)
                    _projects = new Projects($"{ASTServer.AbsoluteUri}api/projects", _httpClient);

                return _projects;
            }
        }

        private Scans _scans;
        public Scans Scans
        {
            get
            {
                if (_scans == null && Connected)
                    _scans = new Scans($"{ASTServer.AbsoluteUri}api/scans", _httpClient);

                return _scans;
            }
        }

        private Reports _reports;
        public Reports Reports
        {
            get
            {
                if (_reports == null && Connected)
                    _reports = new Reports($"{ASTServer.AbsoluteUri}api/reports", _httpClient);

                return _reports;
            }
        }

        private SASTMetadata _SASTMetadata;
        public SASTMetadata SASTMetadata
        {
            get
            {
                if (_SASTMetadata == null && Connected)
                    _SASTMetadata = new SASTMetadata($"{ASTServer.AbsoluteUri}api/sast-metadata", _httpClient);

                return _SASTMetadata;
            }
        }

        private Applications _applications;
        public Applications Applications
        {
            get
            {
                if (_applications == null && Connected)
                    _applications = new Applications($"{ASTServer.AbsoluteUri}api/applications", _httpClient);

                return _applications;
            }
        }

        // Engine SAST results
        private SASTResults _SASTResults;
        public SASTResults SASTResults
        {
            get
            {
                if (_SASTResults == null && Connected)
                    _SASTResults = new SASTResults($"{ASTServer.AbsoluteUri}api/sast-results", _httpClient);

                return _SASTResults;
            }
        }

        // Engine Kics results
        private KicsResults _KicsResults;
        public KicsResults KicsResults
        {
            get
            {
                if (_KicsResults == null && Connected)
                    _KicsResults = new KicsResults($"{ASTServer.AbsoluteUri}api/kics-results", _httpClient);

                return _KicsResults;
            }
        }

        // Engine Scanners results
        private ScannersResults _scannersResults;
        public ScannersResults ScannersResults
        {
            get
            {
                if (_scannersResults == null && Connected)
                    _scannersResults = new ScannersResults($"{ASTServer.AbsoluteUri}api/results", _httpClient);

                return _scannersResults;
            }
        }

        // Engine Results Summary
        private ResultsSummary _resultsSummary;
        public ResultsSummary ResultsSummary
        {
            get
            {
                if (_resultsSummary == null && Connected)
                    _resultsSummary = new ResultsSummary($"{ASTServer.AbsoluteUri}api/scan-summary", _httpClient);

                return _resultsSummary;
            }
        }

        private ResultsOverview _resultsOverview;
        public ResultsOverview ResultsOverview
        {
            get
            {
                if (_resultsOverview == null && Connected)
                    _resultsOverview = new ResultsOverview($"{ASTServer.AbsoluteUri}api/results-overview", _httpClient);

                return _resultsOverview;
            }
        }

        // Configurations
        private Configuration _configuration;
        public Configuration Configuration
        {
            get
            {
                if (_configuration == null && Connected)
                    _configuration = new Configuration($"{ASTServer.AbsoluteUri}api/configuration", _httpClient);

                return _configuration;
            }
        }

        private Repostore _repostore;
        public Repostore Repostore
        {
            get
            {
                if (_repostore == null && Connected)
                    _repostore = new Repostore($"{ASTServer.AbsoluteUri}api/repostore/code", _httpClient);

                return _repostore;
            }
        }

        private Uploads _uploads;
        public Uploads Uploads
        {
            get
            {
                if (_uploads == null && Connected)
                    _uploads = new Uploads($"{ASTServer.AbsoluteUri}api/uploads", _httpClient);

                return _uploads;
            }
        }

        private PresetManagement _presetManagement;
        public PresetManagement PresetManagement
        {
            get
            {
                if (_presetManagement == null && Connected)
                    _presetManagement = new PresetManagement($"{ASTServer.AbsoluteUri}api/presets", _httpClient);

                return _presetManagement;
            }
        }

        private SASTQuery _sastQuery;
        public SASTQuery SASTQuery
        {
            get
            {
                if (_sastQuery == null && Connected)
                    _sastQuery = new SASTQuery(ASTServer.AbsoluteUri, _httpClient);

                return _sastQuery;
            }
        }

        private Logs _logs;
        public Logs Logs
        {
            get
            {
                if (_logs == null && Connected)
                    _logs = new Logs($"{ASTServer.AbsoluteUri}api/logs", _httpClient);

                return _logs;
            }
        }

        #region Connection

        public bool Connected
        {
            get
            {
                try
                {
                    if (_httpClient == null || (_bearerValidTo - DateTime.UtcNow).TotalMinutes < 5)
                    {
                        var token = Autenticate();
                        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                        _bearerValidTo = DateTime.UtcNow.AddSeconds(_bearerExpiresIn - 300);
                    }
                }
                catch (Exception ex)
                {
                    return false;
                }
                return true;
            }
        }

        private void CheckConnection()
        {
            if (!Connected)
                throw new NotSupportedException();
        }

        private string Autenticate()
        {
            var identityURL = $"{AcessControlServer.AbsoluteUri}auth/realms/{Tenant}/protocol/openid-connect/token";

            Dictionary<string, string> kv;

            if (!string.IsNullOrWhiteSpace(KeyApi))
            {
                kv = new Dictionary<string, string>
                {
                    { "grant_type", "refresh_token" },
                    { "client_id", "ast-app" },
                    { "refresh_token", $"{KeyApi}" }
                };
            }
            else
            {
                kv = new Dictionary<string, string>
                {
                    { "grant_type", "client_credentials" },
                    { "client_id", $"{ClientId}" },
                    { "client_secret", $"{ClientSecret}" }
                };
            }

            var req = new HttpRequestMessage(HttpMethod.Post, identityURL) { Content = new FormUrlEncodedContent(kv) };
            req.Headers.UserAgent.Add(new ProductInfoHeaderValue("ASAProgramTracker", "1.0"));

            _httpClient.DefaultRequestHeaders.Add("Accept", "*/*");
            var response = _httpClient.SendAsync(req).Result;
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                JObject accessToken = JsonConvert.DeserializeObject<JObject>(response.Content.ReadAsStringAsync().Result);
                string authToken = ((JProperty)accessToken.First).Value.ToString();
                _bearerExpiresIn = (int)accessToken["expires_in"];
                return authToken;
            }
            throw new Exception(response.Content.ReadAsStringAsync().Result);
        }

        #endregion

        #region Client

        /// <summary>
        /// 
        /// </summary>
        /// <param name="astServer">
        /// US Environment - https://ast.checkmarx.net/
        /// EU Environment - https://eu.ast.checkmarx.net/
        /// </param>
        /// <param name="server">
        /// URL
        /// https://eu.iam.checkmarx.net
        /// https://iam.checkmarx.net
        /// </param>
        /// <param name="tenant"></param>
        /// <param name="apiKey"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public ASTClient(Uri astServer, Uri acessControlServer, string tenant, string apiKey)
        {
            if (astServer == null) throw new ArgumentNullException(nameof(astServer));
            if (acessControlServer == null) throw new ArgumentNullException(nameof(acessControlServer));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentNullException(nameof(apiKey));

            ASTServer = astServer;
            AcessControlServer = acessControlServer;
            Tenant = tenant;
            KeyApi = apiKey;
        }

        public ASTClient(Uri astServer, Uri acessControlServer, string tenant, string clientId, string clientSecret)
        {
            if (astServer == null) throw new ArgumentNullException(nameof(astServer));
            if (acessControlServer == null) throw new ArgumentNullException(nameof(acessControlServer));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));

            ASTServer = astServer;
            AcessControlServer = acessControlServer;
            Tenant = tenant;
            ClientId = clientId;
            ClientSecret = clientSecret;
        }

        #endregion

        #region Applications

        private Services.Applications.ApplicationsCollection _apps { get; set; }
        public Services.Applications.ApplicationsCollection Apps
        {
            get
            {
                if (_apps == null)
                    _apps = GetAllApplications();

                return _apps;
            }
        }

        public Services.Applications.ApplicationsCollection GetAllApplications()
        {
            CheckConnection();

            var getLimit = 20;

            var listApplications = Applications.GetListOfApplicationsAsync(getLimit).Result;
            if (listApplications.TotalCount > getLimit)
            {
                var offset = getLimit;
                bool cont = true;
                do
                {
                    var next = Applications.GetListOfApplicationsAsync(getLimit, offset).Result;
                    if (next.Applications.Any())
                    {
                        next.Applications.ToList().ForEach(o => listApplications.Applications.Add(o));
                        offset += getLimit;

                        if (listApplications.Applications.Count == listApplications.TotalCount) cont = false;
                    }
                    else
                        cont = false;

                } while (cont);
            }

            return listApplications;
        }

        public Services.Applications.Application GetProjectApplication(Guid projectId)
        {
            CheckConnection();

            return Apps.Applications.Where(x => x.ProjectIds.Any(x => x == projectId.ToString()))?.FirstOrDefault();
        }

        #endregion

        #region Projects

        public ProjectsCollection GetAllProjectsDetails()
        {
            CheckConnection();

            //return Projects.GetListOfProjectsAsync(200).Result;

            var getLimit = 500;

            var listProjects = Projects.GetListOfProjectsAsync(getLimit).Result;
            if (listProjects.TotalCount > getLimit)
            {
                var offset = getLimit;
                bool cont = true;
                do
                {
                    var next = Projects.GetListOfProjectsAsync(getLimit, offset).Result;
                    if (next.Projects.Any())
                    {
                        next.Projects.ToList().ForEach(o => listProjects.Projects.Add(o));
                        offset += getLimit;

                        if (listProjects.Projects.Count == listProjects.TotalCount) cont = false;
                    }
                    else
                        cont = false;

                } while (cont);
            }

            return listProjects;
        }

        public void UpdateProjectTags(Guid projectId, IDictionary<string, string> tags)
        {
            CheckConnection();

            if (tags == null)
                throw new ArgumentNullException(nameof(tags));

            var project = Projects.GetProjectAsync(projectId).Result;
            if (project == null)
                throw new Exception($"No project found with id {projectId}");

            ProjectInput input = new ProjectInput
            {
                Tags = tags,
                Name = project.Name,
                Groups = project.Groups,
                RepoUrl = project.RepoUrl,
                MainBranch = project.MainBranch,
                Origin = project.Origin,
                AdditionalProperties = project.AdditionalProperties
            };

            Projects.UpdateProjectAsync(projectId, input).Wait();
        }

        public IEnumerable<string> GetProjectBranches(Guid projectId)
        {
            CheckConnection();

            int startAt = 0;
            int limit = 500;

            while (true)
            {
                var response = Projects.BranchesAsync(projectId, startAt, limit).Result;
                foreach (var result in response)
                {
                    yield return result;
                }

                if (response.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        private IEnumerable<Results> GetSASTScanResultsById(Guid scanId)
        {
            CheckConnection();

            int startAt = 0;
            int limit = 500;

            while (true)
            {
                var response = SASTResults.GetSASTResultsByScanAsync(scanId, startAt, limit).Result;

                if(response.Results == null || !response.Results.Any())
                    yield break;

                foreach (var result in response.Results)
                {
                    yield return result;
                }

                if (response.Results.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        private IEnumerable<KicsResult> GetKicsScanResultsById(Guid scanId)
        {
            CheckConnection();

            int startAt = 0;
            int limit = 500;

            while (true)
            {
                var response = KicsResults.GetKICSResultsByScanAsync(scanId, startAt, limit).Result;
                foreach (var result in response.Results)
                {
                    yield return result;
                }

                if (response.Results.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        private IEnumerable<ScannerResult> GetScannersResultsById(Guid scanId)
        {
            CheckConnection();

            int startAt = 0;
            int limit = 500;

            while (true)
            {
                var response = ScannersResults.GetResultsByScanAsync(scanId, startAt, limit).Result;
                foreach (var result in response.Results)
                {
                    yield return result;
                }

                if (response.Results.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        private IEnumerable<ResultsSummary> GetResultsSummaryById(Guid scanId)
        {
            CheckConnection();

            var response = ResultsSummary.SummaryByScansIdsAsync(new string[] { scanId.ToString() }).Result;
            return response.ScansSummaries;
        }

        public Checkmarx.API.AST.Services.Projects.Project CreateProject(string name, Dictionary<string, string> tags)
        {
            CheckConnection();

            var input = new ProjectInput()
            {
                Name = name,
                Tags = tags
            };

            return Projects.CreateProjectAsync(input).Result;
        }

        #endregion

        #region Scans

        /// <summary>
        /// Get all completed scans from project
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        public IEnumerable<Scan> GetAllASTScans(Guid projectId, string branch = null)
        {
            return GetScans(projectId, branch: branch);
        }

        public Scan GetLastScan(Guid projectId, bool fullScanOnly = false, bool completed = true, string branch = null, ScanTypeEnum scanType = ScanTypeEnum.sast, DateTime? maxScanDate = null)
        {
            var scans = GetScans(projectId, scanType.ToString(), completed, branch, ScanRetrieveKind.All, maxScanDate);
            if (fullScanOnly)
            {
                var fullScans = scans.Where(x => x.Metadata.Configs.Any(x => x.Value != null && !x.Value.Incremental)).OrderByDescending(x => x.CreatedAt);
                if (fullScans.Any())
                    return fullScans.FirstOrDefault();
                else
                    return scans.OrderByDescending(x => x.CreatedAt).FirstOrDefault();
            }
            else
                return scans.FirstOrDefault();
        }

        public Scan GetFirstSASTScan(Guid projectId, string branch = null)
        {
            var scans = GetScans(projectId, "sast", true, branch, ScanRetrieveKind.All);
            if (scans.Any())
            {
                var fullScans = scans.Where(x => x.Metadata.Configs.Any(x => x.Value != null && !x.Value.Incremental)).OrderBy(x => x.CreatedAt);
                if (fullScans.Any())
                    return fullScans.FirstOrDefault();
                else
                    return scans.OrderBy(x => x.CreatedAt).FirstOrDefault();
            }
            else
                return scans.OrderBy(x => x.CreatedAt).FirstOrDefault();
        }

        /// <summary>
        /// Get first locked Scan
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        public Scan GetLockedSASTScan(Guid projectId, string branch = null)
        {
            return GetScans(projectId, "sast", true, branch, ScanRetrieveKind.Locked).FirstOrDefault();
        }

        /// <summary>
        /// Get list of scans, filtered by engine, completion  and scankind
        /// </summary>
        /// <param name="projectId"></param>
        /// <param name="engine"></param>
        /// <param name="completed"></param>
        /// <param name="scanKind"></param>
        /// <returns></returns>
        public IEnumerable<Scan> GetScans(Guid projectId, string engine = null, bool completed = true, string branch = null, ScanRetrieveKind scanKind = ScanRetrieveKind.All, DateTime? maxScanDate = null)
        {
            CheckConnection();

            List<Scan> list = new List<Scan>();

            var scanList = Scans.GetListOfScansAsync(projectId.ToString()).Result;
            var scans = scanList.Scans.Select(x => x);
            if (scans.Any())
            {
                if (completed)
                    scans = scans.Where(x => x.Status == Status.Completed || x.Status == Status.Partial);

                if (!string.IsNullOrEmpty(branch))
                    scans = scans.Where(x => x.Branch.ToLower() == branch.ToLower());

                if (maxScanDate != null)
                    scans = scans.Where(x => x.CreatedAt <= maxScanDate);

                switch (scanKind)
                {
                    case ScanRetrieveKind.First:
                        scans = scans.Take(1);
                        break;
                    case ScanRetrieveKind.Last:
                        scans = scans.Skip(Math.Max(0, scans.Count() - 1));
                        break;
                    case ScanRetrieveKind.All:
                        break;
                }

                foreach (var scan in scans)
                {
                    if (!string.IsNullOrEmpty(engine))
                    {
                        if (scan.Engines != null && scan.Engines.Any(x => x.ToLower() == engine.ToLower()))
                            list.Add(scan);
                    }
                    else
                    {
                        list.Add(scan);
                    }
                }
            }

            return list;
        }

        public ScanDetails GetScanDetails(Guid projectId, Guid scanId)
        {
            var scan = Scans.GetScanAsync(scanId).Result;
            return GetScanDetails(projectId, scan);
        }

        public ScanDetails GetScanDetails(Guid projectId, Scan scan)
        {
            CheckConnection();

            if (scan == null)
                throw new NullReferenceException($"No scan found.");

            ScanDetails scanDetails = new ScanDetails();
            scanDetails.Id = new Guid(scan.Id);
            scanDetails.Status = scan.Status.ToString();
            scanDetails.Successful = scan.Status == Status.Completed || scan.Status == Status.Partial;
            scanDetails.InitiatorName = scan.Initiator;
            scanDetails.Branch = scan.Branch;
            scanDetails.SourceType = scan.SourceType;
            scanDetails.SourceOrigin = scan.SourceOrigin;
            scanDetails.FinishedOn = scan.UpdatedAt.DateTime;
            scanDetails.Duration = scan.UpdatedAt.DateTime - scan.CreatedAt.DateTime;
            scanDetails.Type = scan.Metadata?.Type;
            scanDetails.RepoUrl = scan.Metadata?.Handler?.GitHandler?.RepoUrl;
            scanDetails.UploadUrl = scan.Metadata?.Handler?.UploadHandler?.UploadUrl;

            if (scanDetails.Successful)
            {
                if (scan.StatusDetails == null)
                    throw new Exception($"There is no information about scan engine status.");

                // Known issue where there is a successful scan, but ResultsSummary throws a 404
                // In this case, we are going to try to fetch the sast results in another way
                bool fetchedResultsSuccessfuly = true;
                try
                {
                    var resultsSummary = GetResultsSummaryById(scanDetails.Id).FirstOrDefault();

                    // SAST
                    var sastStatusDetails = scan.StatusDetails.Where(x => x.Name.ToLower() == "sast").FirstOrDefault();
                    if (sastStatusDetails != null)
                    {
                        scanDetails.SASTResults = new ScanResultDetails
                        {
                            Status = sastStatusDetails.Status,
                            Successful = sastStatusDetails.Status.ToLower() == "completed"
                        };

                        if (scanDetails.SASTResults.Successful)
                        {
                            scanDetails = GetSASTScanResultDetails(scanDetails, resultsSummary);

                            // Get sast metadata
                            try
                            {
                                ScanInfo metadata = SASTMetadata.GetMetadataAsync(scanDetails.Id).Result;
                                if (metadata != null)
                                {
                                    scanDetails.Preset = metadata.QueryPreset;
                                    scanDetails.LoC = metadata.Loc;
                                }
                            }
                            catch (Exception ex)
                            {
                                Trace.WriteLine($"Error fetching project {projectId} Preset and LoC. Reason {ex.Message.Replace("\n", " ")}");
                            }

                            if (string.IsNullOrWhiteSpace(scanDetails.Preset))
                                scanDetails.Preset = GetScanPresetFromConfigurations(projectId, scanDetails.Id);

                        }
                        else
                        {
                            scanDetails.SASTResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                        }
                    }

                    // KICS
                    var kicsStatusDetails = scan.StatusDetails.Where(x => x.Name.ToLower() == "kics").FirstOrDefault();
                    if (kicsStatusDetails != null)
                    {
                        scanDetails.KicsResults = new ScanResultDetails();
                        scanDetails.KicsResults.Status = kicsStatusDetails.Status;
                        scanDetails.KicsResults.Successful = kicsStatusDetails.Status.ToLower() == "completed";

                        if (scanDetails.KicsResults.Successful)
                            scanDetails.KicsResults = GetKicsScanResultDetails(scanDetails.KicsResults, resultsSummary);
                        else
                            scanDetails.KicsResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                    }

                    // SCA
                    var scaStatusDetails = scan.StatusDetails.Where(x => x.Name.ToLower() == "sca").FirstOrDefault();
                    if (scaStatusDetails != null)
                    {
                        scanDetails.ScaResults = new ScanResultDetails();
                        scanDetails.ScaResults.Status = scaStatusDetails.Status;
                        scanDetails.ScaResults.Successful = scaStatusDetails.Status.ToLower() == "completed";

                        if (scanDetails.ScaResults.Successful)
                            scanDetails.ScaResults = GetScaScanResultDetails(scanDetails.ScaResults, resultsSummary);
                        else
                            scanDetails.ScaResults.Details = $"Current scan status is {scaStatusDetails.Status}";
                    }
                }
                catch
                {
                    fetchedResultsSuccessfuly = false;
                }

                if (!fetchedResultsSuccessfuly)
                {
                    // SAST
                    var sastStatusDetails = scan.StatusDetails.Where(x => x.Name.ToLower() == "sast").FirstOrDefault();
                    if (sastStatusDetails != null)
                    {
                        scanDetails.SASTResults = new ScanResultDetails();
                        scanDetails.SASTResults.Status = sastStatusDetails.Status;
                        scanDetails.SASTResults.Successful = sastStatusDetails.Status.ToLower() == "completed";

                        if (scanDetails.SASTResults.Successful)
                        {
                            scanDetails = GetSASTScanResultDetailsBydId(scanDetails, scanDetails.Id);

                            // Get sast metadata
                            try
                            {
                                ScanInfo metadata = SASTMetadata.GetMetadataAsync(scanDetails.Id).Result;
                                if (metadata != null)
                                {
                                    scanDetails.Preset = metadata.QueryPreset;
                                    scanDetails.LoC = metadata.Loc;
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Error fetching project {projectId} Preset and LoC.");
                            }
                        }
                        else
                        {
                            scanDetails.SASTResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                        }
                    }

                    // Kicks
                    var kicsStatusDetails = scan.StatusDetails.Where(x => x.Name.ToLower() == "kics").FirstOrDefault();
                    if (kicsStatusDetails != null)
                    {
                        scanDetails.KicsResults = new ScanResultDetails();
                        scanDetails.KicsResults.Status = kicsStatusDetails.Status;
                        scanDetails.KicsResults.Successful = kicsStatusDetails.Status.ToLower() == "completed";

                        if (scanDetails.KicsResults.Successful)
                        {
                            scanDetails.KicsResults = GetKicsScanResultDetailsBydId(scanDetails.KicsResults, scanDetails.Id);
                        }
                        else
                        {
                            scanDetails.KicsResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                        }
                    }

                    // SCA
                    var scaStatusDetails = scan.StatusDetails.Where(x => x.Name.ToLower() == "sca").FirstOrDefault();
                    if (scaStatusDetails != null)
                    {
                        scanDetails.ScaResults = new ScanResultDetails();
                        scanDetails.ScaResults.Status = scaStatusDetails.Status;
                        scanDetails.ScaResults.Successful = scaStatusDetails.Status.ToLower() == "completed";

                        if (scanDetails.ScaResults.Successful)
                        {
                            scanDetails.ScaResults = GetSCAScanResultDetailsBydId(scanDetails.ScaResults, projectId, scanDetails.Id);
                        }
                        else
                        {
                            scanDetails.ScaResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                        }
                    }
                }
            }

            // Languages detected in the SAST, Kicks and SCA scans
            // For now, just adding the SAST languages detected
            if (scanDetails.SASTResults != null && scanDetails.SASTResults.LanguagesDetected != null)
            {
                scanDetails.Languages = string.Join(";", scanDetails.SASTResults.LanguagesDetected.Where(x => x != "Common").Select(x => x).ToList());
            }

            return scanDetails;
        }

        private ScanDetails GetSASTScanResultDetailsBydId(ScanDetails scanDetails, Guid scanId)
        {
            var model = scanDetails.SASTResults;

            var sastResults = GetSASTScanResultsById(scanId).ToList();
            if (sastResults != null)
            {
                scanDetails.SASTVulnerabilities = sastResults;

                var results = sastResults.Where(x => x.State != ResultsState.NOT_EXPLOITABLE);

                model.Id = scanId;
                model.Total = results.Count();
                model.High = results.Where(x => x.Severity == ResultsSeverity.HIGH).Count();
                model.Medium = results.Where(x => x.Severity == ResultsSeverity.MEDIUM).Count();
                model.Low = results.Where(x => x.Severity == ResultsSeverity.LOW).Count();
                model.Info = results.Where(x => x.Severity == ResultsSeverity.INFO).Count();

                model.HighToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.HIGH && x.State == ResultsState.TO_VERIFY).Count();
                model.MediumToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.MEDIUM && x.State == ResultsState.TO_VERIFY).Count();
                model.LowToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.LOW && x.State == ResultsState.TO_VERIFY).Count();

                model.ToVerify = sastResults.Where(x => x.State == ResultsState.TO_VERIFY).Count();
                model.NotExploitableMarked = sastResults.Where(x => x.State == ResultsState.NOT_EXPLOITABLE).Count();
                model.PNEMarked = sastResults.Where(x => x.State == ResultsState.PROPOSED_NOT_EXPLOITABLE).Count();
                model.OtherStates = sastResults.Where(x => x.State != ResultsState.CONFIRMED && x.State != ResultsState.URGENT && x.State != ResultsState.NOT_EXPLOITABLE && x.State != ResultsState.PROPOSED_NOT_EXPLOITABLE && x.State != ResultsState.TO_VERIFY).Count();
                model.LanguagesDetected = sastResults.Select(x => x.LanguageName).Distinct().ToList();
                //model.Queries = report.ScanResults.Sast.Languages.Sum(x => x.Queries.Count());

                try
                {
                    // Scan query categories
                    var scanResultsHigh = results.Where(x => x.Severity == ResultsSeverity.HIGH);
                    var scanResultsMedium = results.Where(x => x.Severity == ResultsSeverity.MEDIUM);
                    var scanResultsLow = results.Where(x => x.Severity == ResultsSeverity.LOW);

                    var scanQueriesHigh = scanResultsHigh.Select(x => x.QueryID).Distinct().ToList();
                    var scanQueriesMedium = scanResultsMedium.Select(x => x.QueryID).Distinct().ToList();
                    var scanQueriesLow = scanResultsLow.Select(x => x.QueryID).Distinct().ToList();

                    model.QueriesHigh = scanQueriesHigh.Count();
                    model.QueriesMedium = scanQueriesMedium.Count();
                    model.QueriesLow = scanQueriesLow.Count();
                    model.Queries = model.QueriesHigh + model.QueriesMedium + model.QueriesLow;
                }
                catch
                {
                    model.QueriesHigh = null;
                    model.QueriesMedium = null;
                    model.QueriesLow = null;
                }
            }

            return scanDetails;
        }

        private ScanDetails GetSASTScanResultDetails(ScanDetails scanDetails, ResultsSummary resultsSummary)
        {
            if (resultsSummary == null)
                return scanDetails;

            var model = scanDetails.SASTResults;

            var sastCounters = resultsSummary.SastCounters;

            model.Id = new Guid(resultsSummary.ScanId);
            model.High = sastCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.HIGH).Sum(x => x.Counter);
            model.Medium = sastCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.MEDIUM).Sum(x => x.Counter);
            model.Low = sastCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.LOW).Sum(x => x.Counter);
            model.Info = sastCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.INFO).Sum(x => x.Counter);
            // ToVerify -> we dont want to include the info vulns
            model.ToVerify = sastCounters.StateCounters.Where(x => x.State == ResultsSummaryState.TO_VERIFY).Sum(x => x.Counter) - model.Info;

            model.Total = sastCounters.TotalCounter;

            model.LanguagesDetected = sastCounters.LanguageCounters.Select(x => x.Language).Distinct().ToList();
            model.Queries = sastCounters.QueriesCounters.Count;

            // Number of queries
            try
            {
                // Scan query categories
                var scanResults = GetSASTScanVulnerabilitiesDetails(model.Id).ToList();

                scanDetails.SASTVulnerabilities = scanResults;

                var scanResultsHigh = scanResults.Where(x => x.Severity == ResultsSeverity.HIGH);
                var scanResultsMedium = scanResults.Where(x => x.Severity == ResultsSeverity.MEDIUM);
                var scanResultsLow = scanResults.Where(x => x.Severity == ResultsSeverity.LOW);

                var scanQueriesHigh = scanResultsHigh.Select(x => x.QueryID).Distinct().ToList();
                var scanQueriesMedium = scanResultsMedium.Select(x => x.QueryID).Distinct().ToList();
                var scanQueriesLow = scanResultsLow.Select(x => x.QueryID).Distinct().ToList();

                model.QueriesHigh = scanQueriesHigh.Count();
                model.QueriesMedium = scanQueriesMedium.Count();
                model.QueriesLow = scanQueriesLow.Count();
                model.Queries = model.QueriesHigh + model.QueriesMedium + model.QueriesLow;

                model.HighToVerify = scanResults.Where(x => x.Severity == ResultsSeverity.HIGH && x.State == ResultsState.TO_VERIFY).Count();
                model.MediumToVerify = scanResults.Where(x => x.Severity == ResultsSeverity.MEDIUM && x.State == ResultsState.TO_VERIFY).Count();
                model.LowToVerify = scanResults.Where(x => x.Severity == ResultsSeverity.LOW && x.State == ResultsState.TO_VERIFY).Count();

                model.ToVerify = scanResults.Where(x => x.State == ResultsState.TO_VERIFY).Count();
                model.NotExploitableMarked = scanResults.Where(x => x.State == ResultsState.NOT_EXPLOITABLE).Count();
                model.PNEMarked = scanResults.Where(x => x.State == ResultsState.PROPOSED_NOT_EXPLOITABLE).Count();
                model.OtherStates = scanResults.Where(x => x.State != ResultsState.CONFIRMED && x.State != ResultsState.URGENT && x.State != ResultsState.NOT_EXPLOITABLE && x.State != ResultsState.PROPOSED_NOT_EXPLOITABLE && x.State != ResultsState.TO_VERIFY).Count();
            }
            catch
            {
                model.QueriesHigh = null;
                model.QueriesMedium = null;
                model.QueriesLow = null;
            }

            return scanDetails;
        }

        private ScanResultDetails GetKicsScanResultDetailsBydId(ScanResultDetails model, Guid scanId)
        {
            var kicsResults = GetKicsScanResultsById(scanId);
            if (kicsResults != null)
            {
                var results = kicsResults.Where(x => x.State != KicsResultState.NOT_EXPLOITABLE);

                model.Id = scanId;
                model.Total = results.Count();
                model.High = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.HIGH).Count();
                model.Medium = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.MEDIUM).Count();
                model.Low = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.LOW).Count();
                model.Info = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.INFO).Count();

                //model.ToVerify = kicsResults.Where(x => x.State == KicsResultState.TO_VERIFY).Count();
            }

            return model;
        }

        private ScanResultDetails GetKicsScanResultDetails(ScanResultDetails model, ResultsSummary resultsSummary)
        {
            if (resultsSummary != null)
            {
                var kicsCounters = resultsSummary.KicsCounters;

                model.Id = new Guid(resultsSummary.ScanId);
                model.High = kicsCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.HIGH).Sum(x => x.Counter);
                model.Medium = kicsCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.MEDIUM).Sum(x => x.Counter);
                model.Low = kicsCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.LOW).Sum(x => x.Counter);
                model.Info = kicsCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.INFO).Sum(x => x.Counter);
                model.ToVerify = kicsCounters.StateCounters.Where(x => x.State == ResultsSummaryState.TO_VERIFY).Sum(x => x.Counter);
                model.Total = kicsCounters.TotalCounter;
            }

            return model;
        }

        private ScanResultDetails GetSCAScanResultDetailsBydId(ScanResultDetails model, Guid projId, Guid scanId)
        {
            // When it is a scan with only SCA engine and 0 results, for some reason other APIs returns null in the sca scan status and results
            // This is the only one i found that returns something
            var resultsOverview = ResultsOverview.ProjectsAsync(new List<string>() { projId.ToString() }).Result;
            if (resultsOverview != null)
            {
                var resultOverview = resultsOverview.FirstOrDefault();
                if (resultOverview != null && resultOverview.scaCounters != null)
                {
                    model.Id = scanId;

                    if (resultOverview.scaCounters.severityCounters != null && resultOverview.scaCounters.severityCounters.Any())
                    {
                        model.High = resultOverview.scaCounters.severityCounters.Where(x => x.Severity.ToUpper() == "HIGH").Sum(x => x.Counter);
                        model.Medium = resultOverview.scaCounters.severityCounters.Where(x => x.Severity.ToUpper() == "MEDIUM").Sum(x => x.Counter);
                        model.Low = resultOverview.scaCounters.severityCounters.Where(x => x.Severity.ToUpper() == "LOW").Sum(x => x.Counter);
                        model.Info = resultOverview.scaCounters.severityCounters.Where(x => x.Severity.ToUpper() == "INFO").Sum(x => x.Counter);
                    }
                    else
                    {
                        model.High = 0;
                        model.Medium = 0;
                        model.Low = 0;
                        model.Info = 0;
                    }

                    if (resultOverview.scaCounters.state != null && resultOverview.scaCounters.state.Any())
                        model.ToVerify = resultOverview.scaCounters.state.Where(x => x.state.ToUpper() == "TO_VERIFY").Sum(x => x.counter);
                    else
                        model.ToVerify = 0;

                    model.Total = resultOverview.scaCounters.totalCounter;
                }
            }

            return model;
        }

        private ScanResultDetails GetScaScanResultDetails(ScanResultDetails model, ResultsSummary resultsSummary)
        {
            if (resultsSummary != null)
            {
                var scaCounters = resultsSummary.ScaCounters;

                model.Id = new Guid(resultsSummary.ScanId);
                model.High = scaCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.HIGH).Sum(x => x.Counter);
                model.Medium = scaCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.MEDIUM).Sum(x => x.Counter);
                model.Low = scaCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.LOW).Sum(x => x.Counter);
                model.Info = scaCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.INFO).Sum(x => x.Counter);
                model.ToVerify = scaCounters.StateCounters.Where(x => x.State == ResultsSummaryState.TO_VERIFY).Sum(x => x.Counter);
                model.Total = scaCounters.TotalCounter;
            }

            return model;
        }

        /// <summary>
        /// Get scan details
        /// </summary>
        /// <param name="projectId"></param>
        /// <param name="scanId"></param>
        /// <param name="createdAt"></param>
        /// <returns></returns>
        public ScanDetails GetScanDetailsOLD(Guid projectId, Guid scanId, DateTime createdAt)
        {
            var result = GetAstScanJsonReport(projectId, scanId);

            ScanDetails scanDetails = new ScanDetails();
            scanDetails.Id = scanId;
            scanDetails.ErrorMessage = result.Item2;

            var report = result.Item1;
            if (report != null)
            {
                var metadata = SASTMetadata.GetMetadataAsync(scanId).Result;
                if (metadata != null)
                {
                    scanDetails.Preset = metadata.QueryPreset;
                    scanDetails.LoC = metadata.Loc;
                }

                var split = report.ScanSummary.ScanCompletedDate.Split(" ");
                DateTime startedOn = createdAt;
                DateTime endOn = Convert.ToDateTime($"{split[0]} {split[1]}");

                scanDetails.FinishedOn = startedOn;
                scanDetails.Duration = endOn - startedOn;

                if (report.ScanSummary.Languages != null && report.ScanSummary.Languages.Any())
                    scanDetails.Languages = string.Join(";", report.ScanSummary.Languages.Where(x => x != "Common").Select(x => x).ToList());

                //Scan Results
                if (report.ScanResults.Sast != null)
                {
                    scanDetails.SASTResults = new ScanResultDetails
                    {
                        Total = (int)report.ScanResults.Sast.Vulnerabilities.Total,
                        High = (int)report.ScanResults.Sast.Vulnerabilities.High,
                        Medium = (int)report.ScanResults.Sast.Vulnerabilities.Medium,
                        Low = (int)report.ScanResults.Sast.Vulnerabilities.Low,
                        Info = (int)report.ScanResults.Sast.Vulnerabilities.Info,
                        ToVerify = GetSASTScanVulnerabilitiesDetails(scanId).Where(x => x.State == Services.SASTResults.ResultsState.TO_VERIFY).Count(),
                        //Queries = report.ScanResults.Sast.Languages.Sum(x => x.Queries.Count()),
                    };

                    if (report.ScanResults.Sast.Languages != null && report.ScanResults.Sast.Languages.Any())
                        scanDetails.SASTResults.LanguagesDetected = report.ScanResults.Sast.Languages.Where(x => x.LanguageName != "Common").Select(x => x.LanguageName).ToList();
                }

                if (report.ScanResults.Sca != null)
                {
                    scanDetails.ScaResults = new ScanResultDetails
                    {
                        Total = (int)report.ScanResults.Sca.Vulnerabilities.Total,
                        High = (int)report.ScanResults.Sca.Vulnerabilities.High,
                        Medium = (int)report.ScanResults.Sca.Vulnerabilities.Medium,
                        Low = (int)report.ScanResults.Sca.Vulnerabilities.Low,
                        Info = (int)report.ScanResults.Sca.Vulnerabilities.Info
                    };
                }

                if (report.ScanResults.Kics != null)
                {
                    scanDetails.KicsResults = new ScanResultDetails
                    {
                        Total = (int)report.ScanResults.Kics.Vulnerabilities.Total,
                        High = (int)report.ScanResults.Kics.Vulnerabilities.High,
                        Medium = (int)report.ScanResults.Kics.Vulnerabilities.Medium,
                        Low = (int)report.ScanResults.Kics.Vulnerabilities.Low,
                        Info = (int)report.ScanResults.Kics.Vulnerabilities.Info
                    };
                }
            }
            else
            {
                try
                {
                    var metadata = SASTMetadata.GetMetadataAsync(scanId).Result;
                    if (metadata != null)
                    {
                        scanDetails.Preset = metadata.QueryPreset;
                        scanDetails.LoC = metadata.Loc;
                    }
                }
                catch
                {
                    scanDetails.ErrorMessage = $"{scanDetails.ErrorMessage} It was not possible to verify the LoC and Preset of the project.";
                }
            }

            return scanDetails;
        }

        public Tuple<ReportResults, string> GetAstScanJsonReport(Guid projectId, Guid scanId)
        {
            CheckConnection();

            string message = string.Empty;

            ScanReportCreateInput sc = new ScanReportCreateInput();
            sc.ReportName = BaseReportCreateInputReportName.ScanReport;
            sc.ReportType = BaseReportCreateInputReportType.Cli;
            sc.FileFormat = BaseReportCreateInputFileFormat.Json;
            sc.Data = new Data { ProjectId = projectId.ToString(), ScanId = scanId.ToString() };

            ReportCreateOutput createReportOutut = null;
            //createReportOutut = Reports.CreateReportAsync(sc).Result;
            int createNumberOfAttempts = 0;
            while (createNumberOfAttempts < 3)
            {
                try
                {
                    createReportOutut = Reports.CreateReportAsync(sc).Result;
                }
                catch
                {
                    System.Threading.Thread.Sleep(500);
                    createNumberOfAttempts++;

                    if (createNumberOfAttempts < 3)
                        continue;
                    else
                        throw;
                }
                break;
            }

            if (createReportOutut != null)
            {
                var createReportId = createReportOutut.ReportId;
                if (createReportId != Guid.Empty)
                {
                    string downloadUrl = null;
                    Guid reportId = createReportId;
                    string reportStatus = "Requested";
                    string pastReportStatus = reportStatus;
                    double aprox_seconds_passed = 0.0;
                    while (reportStatus != "Completed")
                    {
                        System.Threading.Thread.Sleep(1000);
                        aprox_seconds_passed += 1.020;

                        //var statusResponse = Reports.GetReportAsync(reportId, true).GetAwaiter().GetResult();
                        //reportId = statusResponse.ReportId;
                        //reportStatus = statusResponse.Status.ToString();
                        //downloadUrl = statusResponse.Url;

                        int numberOfAttempts = 0;
                        while (numberOfAttempts < 3)
                        {
                            try
                            {
                                var statusResponse = Reports.GetReportAsync(reportId, true).GetAwaiter().GetResult();
                                reportId = statusResponse.ReportId;
                                reportStatus = statusResponse.Status.ToString();
                                downloadUrl = statusResponse.Url;
                            }
                            catch
                            {
                                System.Threading.Thread.Sleep(500);
                                numberOfAttempts++;

                                if (numberOfAttempts < 3)
                                    continue;
                                else
                                    throw;
                            }
                            break;
                        }

                        if (reportStatus != "Requested" && reportStatus != "Completed" && reportStatus != "Started" && reportStatus != "Failed")
                        {
                            //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "Abnormal AST json report status! You may want to [cancel all] and retry.");
                        }
                        if (pastReportStatus != reportStatus)
                        {
                            pastReportStatus = reportStatus;
                        }
                        if (aprox_seconds_passed > 60)
                        {
                            message = "AST Scan json report for project {0} is taking a long time! Try again later.";
                            return new Tuple<ReportResults, string>(null, message);
                        }
                        if (reportStatus == "Failed")
                        {
                            message = "AST Scan API says it could not generate a json report for project {0}. You may want to try again later.";
                            return new Tuple<ReportResults, string>(null, message);
                        }
                    }

                    var reportString = Reports.DownloadScanReportJsonUrl(downloadUrl).GetAwaiter().GetResult();

                    return new Tuple<ReportResults, string>(JsonConvert.DeserializeObject<ReportResults>(reportString), message);
                }
                else
                {
                    message = $"Error getting Report of Scan {scanId}";
                }
            }

            return null;
        }

        public IEnumerable<Results> GetSASTScanVulnerabilitiesDetails(Guid scanId)
        {
            CheckConnection();

            int startAt = 0;
            int limit = 500;

            while (true)
            {
                Services.SASTResults.Response response = null;
                int numTries = 0;
                bool retry = true;
                // Sometimes the call is throwing a 502 Bad Gateway. That is the reason there is this while loop - retries 3 times
                while (retry)
                {
                    try
                    {
                        response = SASTResults.GetSASTResultsByScanAsync(scanId, startAt, limit).Result;
                        retry = false;
                    }
                    catch
                    {
                        retry = numTries < 3;

                        if (!retry)
                            throw;

                        numTries++;

                        System.Threading.Thread.Sleep(500);
                    }
                }
                
                
                if (response.Results != null)
                {
                    foreach (var result in response.Results)
                    {
                        yield return result;
                    }

                    if (response.Results.Count() < limit)
                        yield break;

                    startAt += limit;
                }
                else
                {
                    yield break;
                }
            }
        }

        public Scan ReRunGitScan(Guid projectId, string repoUrl, string branch, string preset, string configuration = null)
        {
            CheckConnection();

            ScanInput scanInput = new ScanInput();
            scanInput.Project = new Services.Scans.Project() { Id = projectId.ToString() };
            scanInput.Type = ScanInputType.Git;
            scanInput.Handler = new Git() { Branch = branch, RepoUrl = repoUrl };

            if (!string.IsNullOrWhiteSpace(configuration))
            {
                scanInput.Config = new List<Config>() {
                    new Config(){
                        Type = ConfigType.Sast,
                        Value = new Dictionary<string, string>() { ["incremental"] = "false", ["presetName"] = preset, ["defaultConfig"] = configuration }
                    }
                };
            }
            else
            {
                scanInput.Config = new List<Config>() {
                    new Config(){
                        Type = ConfigType.Sast,
                        Value = new Dictionary<string, string>() { ["incremental"] = "false", ["presetName"] = preset }
                    }
                };
            }

            return Scans.CreateScanAsync(scanInput).Result;
        }

        public Scan ReRunUploadScan(Guid projectId, Guid lastScanId, string branch, string preset, string configuration = null)
        {
            CheckConnection();

            byte[] source = Repostore.GetSourceCode(lastScanId).Result;

            string uploadUrl = Uploads.GetPresignedURLForUploading().Result;
            Uploads.SendHTTPRequestByFullURL(uploadUrl, source).Wait();

            ScanUploadInput scanInput = new ScanUploadInput();
            scanInput.Project = new Services.Scans.Project() { Id = projectId.ToString() };
            scanInput.Type = ScanInputType.Upload;
            scanInput.Handler = new Upload() { Branch = branch, UploadUrl = uploadUrl };

            if (!string.IsNullOrWhiteSpace(configuration))
            {
                scanInput.Config = new List<Config>() {
                    new Config(){
                        Type = ConfigType.Sast,
                        Value = new Dictionary<string, string>() { ["incremental"] = "false", ["presetName"] = preset, ["defaultConfig"] = configuration }
                    }
                };
            }
            else
            {
                scanInput.Config = new List<Config>() {
                    new Config(){
                        Type = ConfigType.Sast,
                        Value = new Dictionary<string, string>() { ["incremental"] = "false", ["presetName"] = preset }
                    }
                };
            }

            return Scans.CreateScanUploadAsync(scanInput).Result;
        }

        public Scan RunUploadScan(Guid projectId, byte[] source, List<ConfigType> scanTypes, string branch, string preset, string configuration = null)
        {
            CheckConnection();

            string uploadUrl = Uploads.GetPresignedURLForUploading().Result;
            Uploads.SendHTTPRequestByFullURL(uploadUrl, source).Wait();

            ScanUploadInput scanInput = new ScanUploadInput();
            scanInput.Project = new Services.Scans.Project() { Id = projectId.ToString() };
            scanInput.Type = ScanInputType.Upload;
            scanInput.Handler = new Upload() { Branch = branch, UploadUrl = uploadUrl };

            if (!string.IsNullOrWhiteSpace(configuration))
            {
                var configs = new List<Config>();
                foreach (var scanType in scanTypes)
                    configs.Add(new Config()
                    {
                        Type = scanType,
                        Value = new Dictionary<string, string>() { ["incremental"] = "false", ["presetName"] = preset, ["defaultConfig"] = configuration }
                    });

                scanInput.Config = configs;
            }
            else
            {
                var configs = new List<Config>();
                foreach (var scanType in scanTypes)
                    configs.Add(new Config()
                    {
                        Type = scanType,
                        Value = new Dictionary<string, string>() { ["incremental"] = "false", ["presetName"] = preset }
                    });

                scanInput.Config = configs;
            }

            return Scans.CreateScanUploadAsync(scanInput).Result;
        }

        public void DeleteScan(Guid scanId)
        {
            CheckConnection();

            var scan = Scans.GetScanAsync(scanId).Result;
            if (scan != null)
            {
                if (scan.Status == Status.Running || scan.Status == Status.Queued)
                    CancelScan(scanId);

                ////if(scan.SourceType == "Upload")
                ////{
                //    var test = Scans.RecalculateAsync(new RecalculateInput() { Project_id = scan.ProjectId, Id = scanId.ToString(), Branch = scan.Branch, Status = "Queued" }).Result;
                ////}

                Scans.DeleteScanAsync(scanId).Wait();
            }
        }

        public void CancelScan(Guid scanId)
        {
            CheckConnection();

            Scans.CancelScanAsync(scanId, new Body { Status = Status.Canceled.ToString() }).Wait();
        }

        #endregion

        #region Groups

        public void GetGroups()
        {
            CheckConnection();
            var groupAPI = new Services.GroupsResult.GroupsResults($"{ASTServer.AbsoluteUri}auth/realms/{Tenant}/pip/groups", _httpClient);
            var groups = groupAPI.GetGroupsAsync().Result;
        }

        #endregion

        public static Uri GetProjectUri(Uri astServer, Guid projectId)
        {
            if (astServer == null)
                throw new ArgumentNullException(nameof(astServer));

            if (projectId == Guid.Empty)
                throw new ArgumentException("Empty is not a valid project Id");

            return new Uri(astServer, $"projects/{projectId.ToString("D")}/overview");
        }

        #region Configurations

        public IEnumerable<ScanParameter> GetProjectConfigurations(Guid projectId)
        {
            CheckConnection();

            return Configuration.ProjectAllAsync(projectId.ToString()).Result;
        }

        public IEnumerable<ScanParameter> GetTenantConfigurations()
        {
            CheckConnection();

            return Configuration.TenantAllAsync().Result;
        }

        public IEnumerable<ScanParameter> GetScanConfigurations(Guid projectId, Guid scanId)
        {
            CheckConnection();

            return Configuration.ScanAsync(projectId.ToString(), scanId.ToString()).Result;
        }

        public string GetScanPresetFromConfigurations(Guid projectId, Guid scanId)
        {
            var config = GetScanConfigurations(projectId, scanId).Where(x => x.Key == "scan.config.sast.presetName").FirstOrDefault();

            if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                return config.Value;

            return null;
        }

        public IEnumerable<ScanParameter> GetTenantProjectConfigurations()
        {
            return GetTenantConfigurations().Where(x => x.Key == "scan.config.sast.languageMode");
        }

        public string GetProjectConfiguration(Guid projectId)
        {
            //var config = GetProjectConfigurations(projectId).Where(x => x.Key == "scan.config.sast.defaultConfigId").FirstOrDefault();
            var config = GetProjectConfigurations(projectId).Where(x => x.Key == "scan.config.sast.languageMode").FirstOrDefault();
            if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                return config.Value;

            return "Default";
        }

        public Tuple<string, string> GetProjectExclusions(Guid projectId)
        {
            var config = GetProjectConfigurations(projectId).Where(x => x.Key == "scan.config.sast.filter").FirstOrDefault();
            if (config != null && !string.IsNullOrWhiteSpace(config.Value))
            {
                char[] delimiters = new[] { ',', ';' };
                var exclusions = config.Value.Split(delimiters, StringSplitOptions.RemoveEmptyEntries).ToList().Select(x => x.Trim());

                var filesList = exclusions.Where(x => x.StartsWith("."));
                var foldersList = exclusions.Where(x => !x.StartsWith("."));

                var files = filesList.Any() ? string.Join(",", filesList) : string.Empty;
                var folders = foldersList.Any() ? string.Join(",", foldersList) : string.Empty;

                return new Tuple<string, string>(files, folders);
            }

            return new Tuple<string, string>(string.Empty, string.Empty);
        }

        public void SetProjectExclusions(Guid projectId, string exclusions)
        {
            CheckConnection();

            List<ScanParameter> body = new List<ScanParameter>() {
                new ScanParameter()
                {
                    Key = "scan.config.sast.filter",
                    Value = exclusions
                }
            };

            Configuration.UpdateProjectConfigurationAsync(projectId.ToString(), body).Wait();
        }


        public string GetProjectRepoUrl(Guid projectId)
        {
            var config = GetProjectConfigurations(projectId).Where(x => x.Key == "scan.handler.git.repository").FirstOrDefault();
            if (config != null)
                return config.Value;

            return null;
        }

        #endregion

        #region Queries and Presets

        public List<string> GetTenantPresets()
        {
            var config = GetTenantConfigurations().Where(x => x.Key == "scan.config.sast.presetName").FirstOrDefault();
            if (config != null && !string.IsNullOrWhiteSpace(config.ValueTypeParams))
                return config.ValueTypeParams.Split(',').Select(x => x.Trim()).ToList();

            return null;
        }

        public IEnumerable<PresetDetails> GetAllPresetsDetails()
        {
            var presets = GetAllPresets();
            foreach (var preset in presets)
            {
                yield return PresetManagement.GetPresetById(preset.Id).Result;
            }
        }

        public IEnumerable<PresetSummary> GetAllPresets()
        {
            CheckConnection();

            var getLimit = 20;

            var listPresets = PresetManagement.GetPresetsAsync(getLimit).Result;
            if (listPresets.TotalCount > getLimit)
            {
                var offset = getLimit;
                bool cont = true;
                do
                {
                    var next = PresetManagement.GetPresetsAsync(getLimit, offset).Result;
                    if (next.Presets.Any())
                    {
                        next.Presets.ToList().ForEach(o => listPresets.Presets.Add(o));
                        offset += getLimit;

                        if (listPresets.Presets.Count == listPresets.TotalCount) cont = false;
                    }
                    else
                        cont = false;

                } while (cont);
            }

            return listPresets.Presets;
        }

        public IEnumerable<Services.SASTQuery.Query> GetTenantQueries()
        {
            CheckConnection();

            return SASTQuery.GetQueries();
        }

        public IEnumerable<Services.SASTQuery.Query> GetProjectQueries(Guid projectId)
        {
            CheckConnection();

            return SASTQuery.GetQueriesForProject(projectId.ToString());
        }

        public IEnumerable<Services.SASTQuery.Query> GetTeamCorpLevelQueries(Guid projectId)
        {
            CheckConnection();

            return SASTQuery.GetQueriesForProject(projectId.ToString());
        }

        public Services.SASTQuery.Query GetProjectQuery(Guid projectId, string queryPath, bool tenantLevel)
        {
            CheckConnection();

            return SASTQuery.GetQueryForProject(projectId.ToString(), queryPath, tenantLevel);
        }

        public Services.SASTQuery.Query GetCxLevelQuery(string queryPath)
        {
            CheckConnection();

            return SASTQuery.GetCxLevelQuery(queryPath);
        }

        public void SaveProjectQuery(Guid projectId, string queryName, string queryPath, string source)
        {
            CheckConnection();

            SASTQuery.SaveProjectQuery(projectId.ToString(), queryName, queryPath, source);
        }

        public void DeleteProjectQuery(Guid projectId, string queryPath)
        {
            CheckConnection();

            SASTQuery.DeleteProjectQuery(projectId.ToString(), queryPath);
        }

        #endregion

        #region Logs

        public string GetSASTScanLog(Guid scanId)
        {
            return GetScanLogs(scanId.ToString(), "sast");
        }

        public string GetScanLog(Guid scanId, string engine)
        {
            return GetScanLogs(scanId.ToString(), engine);
        }

        private string GetScanLogs(string scanId, string engine)
        {
            CheckConnection();

            string serverRestEndpoint = $"{ASTServer.AbsoluteUri}api/logs/{scanId}/{engine}";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(serverRestEndpoint);
            request.Method = "GET";
            request.Headers.Add("Authorization", Autenticate());
            request.AllowAutoRedirect = false;

            string result = null;

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    if (response.StatusCode == HttpStatusCode.TemporaryRedirect || response.StatusCode == HttpStatusCode.Redirect)
                    {
                        string serverRestEndpoint2 = response.Headers.Get("location");
                        HttpWebRequest request2 = (HttpWebRequest)WebRequest.Create(serverRestEndpoint2);
                        request2.Method = "GET";
                        request2.Headers.Add("Authorization", Autenticate());
                        request2.AllowAutoRedirect = false;
                        using (HttpWebResponse response2 = (HttpWebResponse)request2.GetResponse())
                        {
                            using (Stream dataStream2 = response2.GetResponseStream())
                            {
                                using (StreamReader reader = new StreamReader(dataStream2))
                                {
                                    string responseFromServer = reader.ReadToEnd();
                                    result = responseFromServer;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return result;
        }

        #endregion


    }
}
