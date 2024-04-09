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
using Checkmarx.API.AST.Services.SASTResultsPredicates;
using System.Data;

namespace Checkmarx.API.AST
{
    public class ASTClient
    {
        public Uri AccessControlServer { get; private set; }
        public Uri ASTServer { get; private set; }
        public string Tenant { get; }
        public string KeyApi { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }

        private readonly HttpClient _httpClient = new HttpClient() {
            Timeout = TimeSpan.FromMinutes(30)
        };

        public const string SettingsAPISecuritySwaggerFolderFileFilter = "scan.config.apisec.swaggerFilter";
        public const string SettingsProjectRepoUrl = "scan.handler.git.repository";
        public const string SettingsProjectExclusions = "scan.config.sast.filter";
        public const string SettingsProjectConfiguration = "scan.config.sast.languageMode";
        public const string SettingsProjectPreset = "scan.config.sast.presetName";

        public const string SAST_Engine = "sast";
        public const string SCA_Engine = "sca";
        public const string KICS_Engine = "kics";
        public const string API_Security_Engine = "apisec";
        public const string SCA_Container_Engine = "sca-container";

        private readonly static string CompletedStage = Checkmarx.API.AST.Services.Scans.Status.Completed.ToString();
        
        #region Services

        private Projects _projects;
        public Projects Projects
        {
            get
            {
                if (_projects == null)
                    _projects = new Projects($"{ASTServer.AbsoluteUri}api/projects", _httpClient);

                checkConnection();

                return _projects;
            }
        }

        private Scans _scans;
        public Scans Scans
        {
            get
            {
                if (_scans == null)
                    _scans = new Scans($"{ASTServer.AbsoluteUri}api/scans", _httpClient);

                checkConnection();

                return _scans;
            }
        }

        private Reports _reports;
        public Reports Reports
        {
            get
            {
                if (_reports == null)
                    _reports = new Reports($"{ASTServer.AbsoluteUri}api/reports", _httpClient);

                checkConnection();

                return _reports;
            }
        }

        private SASTMetadata _SASTMetadata;
        public SASTMetadata SASTMetadata
        {
            get
            {
                if (_SASTMetadata == null)
                    _SASTMetadata = new SASTMetadata($"{ASTServer.AbsoluteUri}api/sast-metadata", _httpClient);

                checkConnection();

                return _SASTMetadata;
            }
        }

        private Applications _applications;
        public Applications Applications
        {
            get
            {
                if (_applications == null)
                    _applications = new Applications($"{ASTServer.AbsoluteUri}api/applications", _httpClient);

                checkConnection();

                return _applications;
            }
        }

        // Engine SAST results
        private SASTResults _SASTResults;
        public SASTResults SASTResults
        {
            get
            {
                if (_SASTResults == null)
                    _SASTResults = new SASTResults(ASTServer, _httpClient);

                checkConnection();

                return _SASTResults;
            }
        }

        // Engine SAST results Predicates
        private SASTResultsPredicates _SASTResultsPredicates;
        public SASTResultsPredicates SASTResultsPredicates
        {
            get
            {
                if (_SASTResultsPredicates == null)
                    _SASTResultsPredicates = new SASTResultsPredicates($"{ASTServer.AbsoluteUri}api/sast-results-predicates", _httpClient);

                checkConnection();

                return _SASTResultsPredicates;
            }
        }

        // KICS results
        private KicsResults _kicsResults;
        public KicsResults KicsResults
        {
            get
            {
                if (_kicsResults == null)
                    _kicsResults = new KicsResults($"{ASTServer.AbsoluteUri}api/kics-results", _httpClient);

                checkConnection();

                return _kicsResults;
            }
        }

        // KICS results
        private KICSResultsPredicates _kicsResultsPredicates;
        public KICSResultsPredicates KicsResultsPredicates
        {
            get
            {
                if (_kicsResultsPredicates == null)
                    _kicsResultsPredicates = new KICSResultsPredicates(ASTServer, _httpClient);

                checkConnection();

                return _kicsResultsPredicates;
            }
        }

        // Engine Scanners results
        private ScannersResults _scannersResults;
        public ScannersResults ScannersResults
        {
            get
            {
                if (_scannersResults == null)
                    _scannersResults = new ScannersResults($"{ASTServer.AbsoluteUri}api/results", _httpClient);

                checkConnection();

                return _scannersResults;
            }
        }

        // Engine Results Summary
        private ResultsSummary _resultsSummary;
        public ResultsSummary ResultsSummary
        {
            get
            {
                if (_resultsSummary == null)
                    _resultsSummary = new ResultsSummary($"{ASTServer.AbsoluteUri}api/scan-summary", _httpClient);

                checkConnection();

                return _resultsSummary;
            }
        }

        private ResultsOverview _resultsOverview;
        public ResultsOverview ResultsOverview
        {
            get
            {
                if (_resultsOverview == null)
                    _resultsOverview = new ResultsOverview($"{ASTServer.AbsoluteUri}api/results-overview", _httpClient);

                checkConnection();

                return _resultsOverview;
            }
        }

        // Configurations
        private Configuration _configuration;
        public Configuration Configuration
        {
            get
            {
                if (_configuration == null)
                    _configuration = new Configuration($"{ASTServer.AbsoluteUri}api/configuration", _httpClient);

                checkConnection();

                return _configuration;
            }
        }

        private Repostore _repostore;
        public Repostore Repostore
        {
            get
            {
                if (_repostore == null)
                    _repostore = new Repostore($"{ASTServer.AbsoluteUri}api/repostore/code", _httpClient);

                checkConnection();

                return _repostore;
            }
        }

        private Uploads _uploads;
        public Uploads Uploads
        {
            get
            {
                if (_uploads == null)
                    _uploads = new Uploads($"{ASTServer.AbsoluteUri}api/uploads", _httpClient);

                checkConnection();

                return _uploads;
            }
        }

        private PresetManagement _presetManagement;
        public PresetManagement PresetManagement
        {
            get
            {
                if (_presetManagement == null)
                    _presetManagement = new PresetManagement($"{ASTServer.AbsoluteUri}api/presets", _httpClient);

                checkConnection();

                return _presetManagement;
            }
        }

        private SASTQuery _sastQuery;
        public SASTQuery SASTQuery
        {
            get
            {
                if (_sastQuery == null)
                    _sastQuery = new SASTQuery(ASTServer.AbsoluteUri, _httpClient);

                checkConnection();

                return _sastQuery;
            }
        }


        private SASTQueriesAudit _sastQueriesAudit;
        public SASTQueriesAudit SASTQueriesAudit
        {
            get
            {
                if (_sastQueriesAudit == null)
                    _sastQueriesAudit = new SASTQueriesAudit($"{ASTServer.AbsoluteUri}api/cx-audit", _httpClient);

                checkConnection();

                return _sastQueriesAudit;
            }
        }

        private Logs _logs;
        public Logs Logs
        {
            get
            {
                if (_logs == null)
                    _logs = new Logs($"{ASTServer.AbsoluteUri}api/logs", _httpClient);

                checkConnection();

                return _logs;
            }
        }
        #endregion

        #region Connection

        private int _bearerExpiresIn;
        private DateTime _bearerValidTo;

        public bool Connected
        {
            get
            {
                try
                {
                    if (_httpClient == null || (_bearerValidTo - DateTime.UtcNow).TotalMinutes < 5)
                    {
                        var token = authenticate();
                        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                        _bearerValidTo = DateTime.UtcNow.AddSeconds(_bearerExpiresIn - 300);
                    }
                }
                catch
                {
                    return false;
                }
                return true;
            }
        }

        private void checkConnection()
        {
            if (!Connected)
                throw new NotSupportedException();
        }

        private string authenticate()
        {
            var response = requestAuthenticationToken();
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                JObject accessToken = JsonConvert.DeserializeObject<JObject>(response.Content.ReadAsStringAsync().Result);
                string authToken = ((JProperty)accessToken.First).Value.ToString();
                _bearerExpiresIn = (int)accessToken["expires_in"];
                return authToken;
            }
            throw new Exception(response.Content.ReadAsStringAsync().Result);
        }

        public HttpResponseMessage TestConnection()
        {
            return requestAuthenticationToken();
        }

        private HttpResponseMessage requestAuthenticationToken()
        {
            var identityURL = $"{AccessControlServer.AbsoluteUri}auth/realms/{Tenant}/protocol/openid-connect/token";

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

            return response;
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
        public ASTClient(Uri astServer, Uri accessControlServer, string tenant, string apiKey)
        {
            if (astServer == null) throw new ArgumentNullException(nameof(astServer));
            if (accessControlServer == null) throw new ArgumentNullException(nameof(accessControlServer));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentNullException(nameof(apiKey));

            ASTServer = astServer;
            AccessControlServer = accessControlServer;
            Tenant = tenant;
            KeyApi = apiKey;
        }

        public ASTClient(Uri astServer, Uri accessControlServer, string tenant, string clientId, string clientSecret)
        {
            if (astServer == null) throw new ArgumentNullException(nameof(astServer));
            if (accessControlServer == null) throw new ArgumentNullException(nameof(accessControlServer));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));

            ASTServer = astServer;
            AccessControlServer = accessControlServer;
            Tenant = tenant;
            ClientId = clientId;
            ClientSecret = clientSecret;
        }

        #endregion

        #region Applications


        // TODO: When this cache should be invalidated
        private Services.Applications.ApplicationsCollection _apps { get; set; }
        public Services.Applications.ApplicationsCollection Apps
        {
            get
            {
                if (_apps == null)
                    _apps = getAllApplications();

                return _apps;
            }
        }

        private Services.Applications.ApplicationsCollection getAllApplications(int getLimit = 20)
        {
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
            return Apps.Applications?.Where(x => x.ProjectIds.Contains(projectId))?.FirstOrDefault();
        }

        #endregion

        #region Projects

        public ProjectsCollection GetAllProjectsDetails(int getLimit = 500)
        {
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

        public RichProject GetProject(Guid id)
        {
            if (id == Guid.Empty)
                throw new ArgumentNullException(nameof(id));

            return Projects.GetProjectAsync(id).Result;
        }

        public void UpdateProjectTags(Guid projectId, IDictionary<string, string> tags)
        {
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

        public IEnumerable<string> GetProjectBranches(Guid projectId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

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

        public IEnumerable<KicsResult> GetKicsScanResultsById(Guid scanId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

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

        /// <summary>
        /// For SCA it just returns the vulnerabilities.
        /// </summary>
        /// <param name="scanId">Id of the scan</param>
        /// <param name="engines"></param>
        /// <returns></returns>
        public IEnumerable<ScannerResult> GetScannersResultsById(Guid scanId, params string[] engines)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            int startAt = 0;
            int limit = 500;

            while (true)
            {
                var response = ScannersResults.GetResultsByScanAsync(scanId, startAt, limit).Result;
                foreach (var result in response.Results)
                {
                    if (!engines.Any() || (engines.Any() && engines.Contains(result.Type, StringComparer.InvariantCultureIgnoreCase)))
                        yield return result;
                }

                if (response.Results.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        private IEnumerable<ResultsSummary> GetResultsSummaryById(Guid scanId)
        {
            return ResultsSummary.SummaryByScansIdsAsync(new Guid[] { scanId }).Result.ScansSummaries;
        }

        public Checkmarx.API.AST.Services.Projects.Project CreateProject(string name, Dictionary<string, string> tags)
        {
            return Projects.CreateProjectAsync(new ProjectInput()
            {
                Name = name,
                Tags = tags
            }).Result;
        }

        public static Uri GetProjectUri(Uri astServer, Guid projectId)
        {
            if (astServer == null)
                throw new ArgumentNullException(nameof(astServer));

            if (projectId == Guid.Empty)
                throw new ArgumentException("Empty is not a valid project Id");

            return new Uri(astServer, $"projects/{projectId.ToString("D")}/overview");
        }

        #endregion

        #region Scans

        /// <summary>
        /// Get all completed scans from project
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        public IEnumerable<Scan> GetAllScans(Guid projectId, string branch = null)
        {
            return GetScans(projectId, branch: branch);
        }

        public Scan GetLastScan(Guid projectId, bool fullScanOnly = false, bool completed = true, string branch = null, ScanTypeEnum scanType = ScanTypeEnum.sast, DateTime? maxScanDate = null)
        {
            if (!fullScanOnly && !maxScanDate.HasValue)
            {
                var scanStatus = completed ? CompletedStage : null;

                var scans = this.Projects.GetProjectLastScan(new List<Guid>() { projectId }, scan_status: scanStatus, branch: branch, engine: scanType.ToString()).Result;

                if (scans.ContainsKey(projectId.ToString()))
                    return this.Scans.GetScanAsync(new Guid(scans[projectId.ToString()].Id)).Result;

                return null;
            }
            else
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
        }

        public Scan GetFirstSASTScan(Guid projectId, string branch = null)
        {
            var scans = GetScans(projectId, SAST_Engine, true, branch, ScanRetrieveKind.All);
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
            return GetScans(projectId, SAST_Engine, true, branch, ScanRetrieveKind.Locked).FirstOrDefault();
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
            List<Scan> list = new List<Scan>();

            var scanList = Scans.GetListOfScansAsync(projectId).Result;
            var scans = scanList.Scans.Select(x => x);
            if (scans.Any())
            {
                if (completed)
                    scans = scans.Where(x => x.Status == Status.Completed || x.Status == Status.Partial);

                if (!string.IsNullOrEmpty(branch))
                    scans = scans.Where(x => x.Branch == branch);

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
                        if (scan.Engines != null && scan.Engines.Any(x => x == engine &&
                            (scan.Status == Status.Completed || scan.StatusDetails?.SingleOrDefault(x => x.Name == engine)?.Status == CompletedStage)))
                        {
                            list.Add(scan);
                        }
                    }
                    else
                    {
                        list.Add(scan);
                    }
                }
            }

            return list;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="projectId"></param>
        /// <param name="scanId"></param>
        /// <returns></returns>
        public ScanDetails GetScanDetails(Guid scanId)
        {
            return GetScanDetails(Scans.GetScanAsync(scanId).Result);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="projectId"></param>
        /// <param name="scan"></param>
        /// <returns></returns>
        /// <exception cref="NullReferenceException"></exception>
        /// <exception cref="Exception"></exception>
        public ScanDetails GetScanDetails(Scan scan)
        {
            if (scan == null)
                throw new NullReferenceException($"No scan found.");

            ScanDetails scanDetails = new()
            {
                Id = scan.Id,
                Status = scan.Status.ToString(),
                Successful = scan.Status == Status.Completed || scan.Status == Status.Partial,
                InitiatorName = scan.Initiator,
                Branch = scan.Branch,
                SourceType = scan.SourceType,
                SourceOrigin = scan.SourceOrigin,
                FinishedOn = scan.UpdatedAt.DateTime,
                Duration = scan.UpdatedAt.DateTime - scan.CreatedAt.DateTime,
                Type = scan.Metadata?.Type,
                RepoUrl = scan.Metadata?.Handler?.GitHandler?.RepoUrl,
                UploadUrl = scan.Metadata?.Handler?.UploadHandler?.UploadUrl
            };

            if (scanDetails.Successful)
            {
                if (scan.StatusDetails == null)
                    throw new Exception($"There is no information about scan engine status.");


                bool fetchedResultsSuccessfully = true;
                try
                {
                    var resultsSummary = GetResultsSummaryById(scanDetails.Id).FirstOrDefault();

                    // Known issue where there is a successful scan, but ResultsSummary throws a 404
                    // In this case, we are going to try to fetch the sast results in another way

                    #region SAST

                    var sastStatusDetails = scan.StatusDetails.SingleOrDefault(x => x.Name == SAST_Engine);
                    if (sastStatusDetails != null)
                    {
                        scanDetails.SASTResults = new ScanResultDetails
                        {
                            Status = sastStatusDetails.Status,
                            Successful = sastStatusDetails.Status == CompletedStage
                        };

                        if (scanDetails.SASTResults.Successful)
                        {
                            scanDetails = getSASTScanResultDetails(scanDetails, resultsSummary);

                            // Get sast metadata
                            try
                            {
                                // TODO: Refactor this to avoid throwing exceptions all the time regarding a know situation.
                                ScanInfo metadata = SASTMetadata.GetMetadataAsync(scanDetails.Id).Result;
                                if (metadata != null)
                                {
                                    scanDetails.Preset = metadata.QueryPreset;
                                    scanDetails.LoC = metadata.Loc;
                                }
                            }
                            catch (Exception ex)
                            {
                                Trace.WriteLine($"Error fetching project {scan.ProjectId} Preset and LoC. Reason {ex.Message.Replace("\n", " ")}");
                            }

                            if (string.IsNullOrWhiteSpace(scanDetails.Preset))
                                scanDetails.Preset = GetScanPresetFromConfigurations(scan.ProjectId, scanDetails.Id);

                        }
                        else
                        {
                            scanDetails.SASTResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                        }
                    }
                    #endregion

                    #region KICS

                    var kicsStatusDetails = scan.StatusDetails.SingleOrDefault(x => x.Name == KICS_Engine);
                    if (kicsStatusDetails != null)
                    {
                        scanDetails.KicsResults = new ScanResultDetails();
                        scanDetails.KicsResults.Status = kicsStatusDetails.Status;
                        scanDetails.KicsResults.Successful = kicsStatusDetails.Status == CompletedStage;

                        if (scanDetails.KicsResults.Successful)
                            scanDetails.KicsResults = getKicsScanResultDetails(scanDetails.KicsResults, resultsSummary);
                        else
                            scanDetails.KicsResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                    }
                    #endregion

                    #region SCA
                    var scaStatusDetails = scan.StatusDetails.SingleOrDefault(x => x.Name == SCA_Engine);
                    if (scaStatusDetails != null)
                    {
                        scanDetails.ScaResults = new ScanResultDetails();
                        scanDetails.ScaResults.Status = scaStatusDetails.Status;
                        scanDetails.ScaResults.Successful = scaStatusDetails.Status == CompletedStage;

                        if (scanDetails.ScaResults.Successful)
                            scanDetails.ScaResults = getScaScanResultDetails(scanDetails.ScaResults, resultsSummary);
                        else
                            scanDetails.ScaResults.Details = $"Current scan status is {scaStatusDetails.Status}";
                    }
                    #endregion
                }
                catch
                {
                    fetchedResultsSuccessfully = false;
                }

                if (!fetchedResultsSuccessfully)
                {
                    #region SAST

                    var sastStatusDetails = scan.StatusDetails.SingleOrDefault(x => x.Name == SAST_Engine);
                    if (sastStatusDetails != null)
                    {
                        scanDetails.SASTResults = new ScanResultDetails();
                        scanDetails.SASTResults.Status = sastStatusDetails.Status;
                        scanDetails.SASTResults.Successful = sastStatusDetails.Status == CompletedStage;

                        if (scanDetails.SASTResults.Successful)
                        {
                            scanDetails = getSASTScanResultDetailsBydId(scanDetails, scanDetails.Id);

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
                                Console.WriteLine($"Error fetching project {scan.ProjectId} Preset and LoC because {ex.Message}.");
                            }
                        }
                        else
                        {
                            scanDetails.SASTResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                        }
                    }

                    #endregion

                    #region  Kicks

                    var kicsStatusDetails = scan.StatusDetails.SingleOrDefault(x => x.Name == KICS_Engine);
                    if (kicsStatusDetails != null)
                    {
                        scanDetails.KicsResults = new ScanResultDetails
                        {
                            Status = kicsStatusDetails.Status,
                            Successful = kicsStatusDetails.Status == CompletedStage
                        };

                        if (scanDetails.KicsResults.Successful)
                        {
                            scanDetails.KicsResults = getKicsScanResultDetailsBydId(scanDetails.KicsResults, scanDetails.Id);
                        }
                        else
                        {
                            scanDetails.KicsResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                        }
                    }

                    #endregion

                    #region SCA

                    var scaStatusDetails = scan.StatusDetails.Where(x => x.Name == SCA_Engine).FirstOrDefault();
                    if (scaStatusDetails != null)
                    {
                        scanDetails.ScaResults = new ScanResultDetails();
                        scanDetails.ScaResults.Status = scaStatusDetails.Status;
                        scanDetails.ScaResults.Successful = scaStatusDetails.Status == CompletedStage;

                        if (scanDetails.ScaResults.Successful)
                        {
                            scanDetails.ScaResults = getSCAScanResultDetailsBydId(scanDetails.ScaResults, scan.ProjectId, scanDetails.Id);
                        }
                        else
                        {
                            scanDetails.ScaResults.Details = $"Current scan status is {sastStatusDetails.Status}";
                        }
                    }

                    #endregion
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

        /// <summary>
        /// Very performance intensive.
        /// </summary>
        /// <param name="scanDetails"></param>
        /// <param name="scanId"></param>
        /// <returns></returns>
        private ScanDetails getSASTScanResultDetailsBydId(ScanDetails scanDetails, Guid scanId)
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

        /// <summary>
        /// Very performance intensive.
        /// </summary>
        /// <param name="scanDetails"></param>
        /// <param name="resultsSummary"></param>
        /// <returns></returns>
        private ScanDetails getSASTScanResultDetails(ScanDetails scanDetails, ResultsSummary resultsSummary)
        {
            if (resultsSummary == null)
                return scanDetails;

            var model = scanDetails.SASTResults;

            var sastCounters = resultsSummary.SastCounters;

            model.Id = new Guid(resultsSummary.ScanId);
            model.High = sastCounters.SeverityCounters
                .Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.HIGH).Sum(x => x.Counter);
            model.Medium = sastCounters.SeverityCounters
                .Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.MEDIUM).Sum(x => x.Counter);
            model.Low = sastCounters.SeverityCounters
                .Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.LOW).Sum(x => x.Counter);
            model.Info = sastCounters.SeverityCounters
                .Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.INFO).Sum(x => x.Counter);

            // ToVerify -> we dont want to include the info vulns
            model.ToVerify = sastCounters.StateCounters.Where(x => x.State == ResultsSummaryState.TO_VERIFY).Sum(x => x.Counter) - model.Info;

            model.Total = sastCounters.TotalCounter;

            model.LanguagesDetected = sastCounters.LanguageCounters.Select(x => x.Language).Distinct().ToList();
            model.Queries = sastCounters.QueriesCounters.Count;

            // Number of queries
            try
            {
                // Scan query categories
                var scanResults = GetSASTScanResultsById(model.Id).ToList();

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

        private ScanResultDetails getKicsScanResultDetailsBydId(ScanResultDetails model, Guid scanId)
        {
            var kicsResults = GetKicsScanResultsById(scanId);
            if (kicsResults != null)
            {
                var results = kicsResults.Where(x => x.State != KicsStateEnum.NOT_EXPLOITABLE);

                model.Id = scanId;
                model.Total = results.Count();
                model.High = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.HIGH).Count();
                model.Medium = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.MEDIUM).Count();
                model.Low = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.LOW).Count();
                model.Info = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.INFO).Count();
                model.ToVerify = kicsResults.Where(x => x.State == KicsStateEnum.TO_VERIFY).Count();
            }

            return model;
        }

        private ScanResultDetails getKicsScanResultDetails(ScanResultDetails model, ResultsSummary resultsSummary)
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

        private ScanResultDetails getSCAScanResultDetailsBydId(ScanResultDetails model, Guid projId, Guid scanId)
        {
            // When it is a scan with only SCA engine and 0 results, for some reason other APIs returns null in the sca scan status and results
            // This is the only one i found that returns something
            var resultsOverview = ResultsOverview.ProjectsAsync(new List<Guid>() { projId }).Result;
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

        private ScanResultDetails getScaScanResultDetails(ScanResultDetails model, ResultsSummary resultsSummary)
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

        public Tuple<ReportResults, string> GetAstScanJsonReport(Guid projectId, Guid scanId)
        {
            checkConnection();

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

        public IEnumerable<Results> GetSASTScanResultsById(Guid scanId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));


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

        public Scan ReRunGitScan(Guid projectId, string repoUrl, IEnumerable<ConfigType> scanTypes, string branch, string preset, string configuration = null)
        {
            checkConnection();

            ScanInput scanInput = new ScanInput();
            scanInput.Project = new Services.Scans.Project() { Id = projectId.ToString() };
            scanInput.Type = ScanInputType.Git;
            scanInput.Handler = new Git() { Branch = branch, RepoUrl = repoUrl };

            if (!string.IsNullOrWhiteSpace(configuration))
            {
                var configs = new List<Config>();
                foreach (var scanType in scanTypes)
                {
                    configs.Add(new Config()
                    {
                        Type = scanType,
                        Value = new Dictionary<string, string>()
                        {
                            ["incremental"] = "false",
                            ["presetName"] = preset,
                            ["defaultConfig"] = configuration
                        }
                    });
                }

                scanInput.Config = configs;
            }
            else
            {
                var configs = new List<Config>();
                foreach (var scanType in scanTypes)
                    configs.Add(new Config()
                    {
                        Type = scanType,
                        Value = new Dictionary<string, string>()
                        {
                            ["incremental"] = "false",
                            ["presetName"] = preset
                        }
                    });

                scanInput.Config = configs;
            }

            return Scans.CreateScanAsync(scanInput).Result;
        }

        public Scan ReRunUploadScan(Guid projectId, Guid lastScanId, IEnumerable<ConfigType> scanTypes, string branch, string preset, string configuration = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (lastScanId == Guid.Empty)
                throw new ArgumentNullException(nameof(lastScanId));

            checkConnection();

            byte[] source = Repostore.GetSourceCode(lastScanId).Result;

            return RunUploadScan(projectId, source, scanTypes, branch, preset, configuration);
        }

        public Scan RunUploadScan(Guid projectId, byte[] source, IEnumerable<ConfigType> scanTypes, string branch, string preset, string configuration = null)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            if (scanTypes == null || !scanTypes.Any())
                throw new ArgumentNullException(nameof(scanTypes));

            checkConnection();

            string uploadUrl = Uploads.GetPresignedURLForUploading().Result;
            Uploads.SendHTTPRequestByFullURL(uploadUrl, source).Wait();

            ScanUploadInput scanInput = new()
            {
                Project = new Services.Scans.Project()
                {
                    Id = projectId.ToString()
                },
                Type = ScanInputType.Upload,
                Handler = new Upload()
                {
                    Branch = branch,
                    UploadUrl = uploadUrl
                }
            };

            if (!string.IsNullOrWhiteSpace(configuration))
            {
                var configs = new List<Config>();
                foreach (var scanType in scanTypes)
                {
                    configs.Add(new Config()
                    {
                        Type = scanType,
                        Value = new Dictionary<string, string>()
                        {
                            ["incremental"] = "false",
                            ["presetName"] = preset,
                            ["defaultConfig"] = configuration
                        }
                    });
                }

                scanInput.Config = configs;
            }
            else
            {
                var configs = new List<Config>();
                foreach (var scanType in scanTypes)
                    configs.Add(new Config()
                    {
                        Type = scanType,
                        Value = new Dictionary<string, string>()
                        {
                            ["incremental"] = "false",
                            ["presetName"] = preset
                        }
                    });

                scanInput.Config = configs;
            }

            return Scans.CreateScanUploadAsync(scanInput).Result;
        }

        public void DeleteScan(Guid scanId)
        {
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
            Scans.CancelScanAsync(scanId, new Body { Status = Status.Canceled.ToString() }).Wait();
        }

        #endregion

        #region Results

        public bool MarkSASTResult(Guid projectId, Results result, IEnumerable<PredicateWithCommentJSON> history, bool updateSeverity = true, bool updateState = true, bool updateComment = true)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (history == null)
                throw new NullReferenceException(nameof(history));

            if (result == null)
                throw new ArgumentNullException(nameof(result));

            List<PredicateBySimiliartyIdBody> body = [];

            foreach (var predicate in history)
            {
                PredicateBySimiliartyIdBody newBody = new PredicateBySimiliartyIdBody
                {
                    SimilarityId = predicate.SimilarityId.ToString(),
                    ProjectId = projectId,
                    Severity = updateSeverity ? predicate.Severity : result.Severity,
                    State = updateState ? predicate.State : result.State,
                    Comment = updateComment ? predicate.Comment : null
                };

                body.Add(newBody);
            }

            if (body.Any())
            {
                SASTResultsPredicates.PredicateBySimiliartyIdAndProjectIdAsync(body).Wait();
                return true;
            }

            return false;
        }

        public void MarkSASTResult(Guid projectId, long similarityId, ResultsSeverity severity, ResultsState state, string comment = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            PredicateBySimiliartyIdBody newBody = new PredicateBySimiliartyIdBody
            {
                SimilarityId = similarityId.ToString(),
                ProjectId = projectId,
                Severity = severity,
                State = state
            };

            if (!string.IsNullOrWhiteSpace(comment))
                newBody.Comment = comment;

            SASTResultsPredicates.PredicateBySimiliartyIdAndProjectIdAsync(new PredicateBySimiliartyIdBody[] { newBody }).Wait();
        }

        /// <summary>
        /// Mark kics results.
        /// </summary>
        /// <remarks>the same as SAST </remarks>
        /// <param name="projectId"></param>
        /// <returns></returns>
        /// <exception cref="NotSupportedException"></exception>
        public bool MarkKICSResult(string similarityId, Guid projectId, Services.KicsResults.SeverityEnum severity, KicsStateEnum state, string comment = null)
        {
            if (string.IsNullOrWhiteSpace(similarityId))
                throw new ArgumentNullException(nameof(similarityId));

            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            KicsResultsPredicates.UpdateAsync(
                new[] { new POSTPredicate (){
                    SimilarityId = similarityId,
                    ProjectId = projectId,
                    Severity = severity,
                    State = state,
                    Comment = comment
                }
            }).Wait();

            return true;
        }

        public bool MarkSCAResult(Guid projectId)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region Groups

        public void GetGroups()
        {
            checkConnection();
            var groupAPI = new Services.GroupsResult.GroupsResults($"{ASTServer.AbsoluteUri}auth/realms/{Tenant}/pip/groups", _httpClient);
            var groups = groupAPI.GetGroupsAsync().Result;
        }

        #endregion

        #region Configurations

        public Dictionary<string, ScanParameter> GetTenantConfigurations()
        {
            return Configuration.TenantAllAsync().Result?.ToDictionary(x => x.Key, y => y);
        }

        public Dictionary<string, ScanParameter> GetProjectConfigurations(Guid projectId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            return Configuration.ProjectAllAsync(projectId).Result?.ToDictionary(x => x.Key, y => y);
        }

        public Dictionary<string, ScanParameter> GetScanConfigurations(Guid projectId, Guid scanId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (scanId == Guid.Empty)
                throw new ArgumentException(nameof(scanId));

            return Configuration.ScanAsync(projectId, scanId).Result?.ToDictionary(x => x.Key, y => y);
        }

        public void DeleteTenantConfiguration(string config_keys)
        {
            if (string.IsNullOrWhiteSpace(config_keys))
                throw new ArgumentException(nameof(config_keys));

            Configuration.TenantDELETEParameterAsync(config_keys).Wait();
        }

        public void DeleteProjectConfiguration(Guid projectId, string config_keys)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(config_keys))
                throw new ArgumentException(nameof(config_keys));

            Configuration.ProjectDELETEParameterAsync(projectId, config_keys).Wait();
        }

        public string GetScanPresetFromConfigurations(Guid projectId, Guid scanId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (scanId == Guid.Empty)
                throw new ArgumentException(nameof(scanId));

            var configuration = GetScanConfigurations(projectId, scanId);
            if (configuration.ContainsKey(SettingsProjectPreset))
            {
                var config = configuration[SettingsProjectPreset];

                if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                    return config.Value;
            }

            return null;
        }

        public IEnumerable<ScanParameter> GetTenantProjectConfigurations()
        {
            return GetTenantConfigurations().Where(x => x.Value.Key == SettingsProjectConfiguration).Select(x => x.Value);
        }

        public string GetProjectRepoUrl(Guid projectId) => getConfig(projectId, SettingsProjectRepoUrl);

        public string GetProjectConfiguration(Guid projectId) => getConfig(projectId, SettingsProjectConfiguration);

        public string GetProjectExclusions(Guid projectId) => getConfig(projectId, SettingsProjectExclusions);

        public string GetProjectAPISecuritySwaggerFolderFileFilter(Guid projectId) => getConfig(projectId, SettingsAPISecuritySwaggerFolderFileFilter);

        public void SetProjectExclusions(Guid projectId, string exclusions) => setConfig(projectId, SettingsProjectExclusions, exclusions);

        private string getConfig(Guid projectId, string configKey)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            var configuration = GetProjectConfigurations(projectId);
            if (configuration.ContainsKey(configKey))
            {
                var config = configuration[configKey];

                if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                    return config.Value;
            }

            return null;
        }

        private void setConfig(Guid projectId, string key, string value)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException(nameof(value));

            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException(nameof(key));

            List<ScanParameter> body = new List<ScanParameter>() {
                new ScanParameter()
                {
                    Key = key,
                    Value = value
                }
            };

            Configuration.UpdateProjectConfigurationAsync(projectId.ToString(), body).Wait();
        }


        public Tuple<string, string> GetProjectFilesAndFoldersExclusions(Guid projectId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            var config = GetProjectExclusions(projectId);
            if (!string.IsNullOrWhiteSpace(config))
            {
                char[] delimiters = new[] { ',', ';' };
                var exclusions = config.Split(delimiters, StringSplitOptions.RemoveEmptyEntries).ToList().Select(x => x.Trim());

                var filesList = exclusions.Where(x => x.StartsWith("."));
                var foldersList = exclusions.Where(x => !x.StartsWith("."));

                var files = filesList.Any() ? string.Join(",", filesList) : string.Empty;
                var folders = foldersList.Any() ? string.Join(",", foldersList) : string.Empty;

                return new Tuple<string, string>(files, folders);
            }

            return new Tuple<string, string>(string.Empty, string.Empty);
        }

        public string GetTenantAPISecuritySwaggerFolderFileFilter()
        {
            var configuration = GetTenantConfigurations();
            if (configuration.ContainsKey(SettingsAPISecuritySwaggerFolderFileFilter))
            {
                var config = configuration[SettingsAPISecuritySwaggerFolderFileFilter];

                if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                    return config.Value;
            }

            return null;
        }

        public void SetTenantAPISecuritySwaggerFolderFileFilter(string filter = null, bool allowOverride = false)
        {
            if (filter == null)
            {
                // Delete current value
                DeleteTenantConfiguration(SettingsAPISecuritySwaggerFolderFileFilter);
                return;
            }

            List<ScanParameter> body = new List<ScanParameter>() {
                new ScanParameter()
                {
                    Key = SettingsAPISecuritySwaggerFolderFileFilter,
                    Value = filter,
                    AllowOverride = allowOverride
                }
            };

            Configuration.UpdateTenantConfigurationAsync(body).Wait();
        }

        public void SetProjectAPISecuritySwaggerFolderFileFilter(Guid projectId, string filter = null, bool allowOverride = false)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (filter == null)
            {
                // Delete current parameter
                DeleteProjectConfiguration(projectId, SettingsAPISecuritySwaggerFolderFileFilter);
                return;
            }

            List<ScanParameter> body = new List<ScanParameter>() {
                new ScanParameter()
                {
                    Key = SettingsAPISecuritySwaggerFolderFileFilter,
                    Value = filter,
                    AllowOverride = allowOverride
                }
            };

            Configuration.UpdateProjectConfigurationAsync(projectId.ToString(), body).Wait();
        }

        #endregion

        #region Queries and Presets

        public List<string> GetTenantPresets()
        {
            var configuration = GetTenantConfigurations();
            if (configuration.ContainsKey(SettingsProjectPreset))
            {
                var config = configuration[SettingsProjectPreset];

                if (config != null && !string.IsNullOrWhiteSpace(config.ValueTypeParams))
                    return config.ValueTypeParams.Split(',').Select(x => x.Trim()).ToList();
            }

            return null;
        }

        public IEnumerable<PresetDetails> GetAllPresetsDetails()
        {
            foreach (var preset in GetAllPresets())
            {
                yield return PresetManagement.GetPresetById(preset.Id).Result;
            }
        }

        public IEnumerable<PresetSummary> GetAllPresets(int limit = 20)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            var listPresets = PresetManagement.GetPresetsAsync(limit).Result;
            if (listPresets.TotalCount > limit)
            {
                var offset = limit;
                bool cont = true;
                do
                {
                    var next = PresetManagement.GetPresetsAsync(limit, offset).Result;
                    if (next.Presets.Any())
                    {
                        next.Presets.ToList().ForEach(o => listPresets.Presets.Add(o));
                        offset += limit;

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
            return SASTQuery.GetQueries();
        }

        public Dictionary<string, Services.SASTQuery.Query> GetProjectQueries(Guid projectId)
        {
            // The Distinct is a workaround... not the solution.
            return SASTQuery.GetQueriesForProject(projectId).DistinctBy(x => x.Id).ToDictionary(x => x.Id, StringComparer.InvariantCultureIgnoreCase);
        }

        public IEnumerable<Services.SASTQuery.Query> GetTeamCorpLevelQueries(Guid projectId)
        {
            return SASTQuery.GetQueriesForProject(projectId).Where(x => x.IsExecutable);
        }

        public Services.SASTQuery.Query GetProjectQuery(Guid projectId, string queryPath, bool tenantLevel)
        {
            return SASTQuery.GetQueryForProject(projectId, queryPath, tenantLevel);
        }

        public Services.SASTQuery.Query GetCxLevelQuery(string queryPath)
        {
            return SASTQuery.GetCxLevelQuery(queryPath);
        }

        public void SaveProjectQuery(Guid projectId, string queryName, string queryPath, string source)
        {
            SASTQuery.SaveProjectQuery(projectId.ToString(), queryName, queryPath, source);
        }

        public void DeleteProjectQuery(Guid projectId, string queryPath)
        {
            SASTQuery.DeleteProjectQuery(projectId, queryPath);
        }

        #endregion

        #region Logs

        public string GetSASTScanLog(Guid scanId)
        {
            return GetScanLogs(scanId, SAST_Engine);
        }

        public string GetScanLog(Guid scanId, string engine)
        {
            return GetScanLogs(scanId, engine);
        }

        private string GetScanLogs(Guid scanId, string engine)
        {
            if (string.IsNullOrEmpty(engine))
                throw new ArgumentNullException(nameof(engine));

            // return Logs.GetEngineLogsAsync(scanId, engine).Result;

            string serverRestEndpoint = $"{ASTServer.AbsoluteUri}api/logs/{scanId}/{engine}";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(serverRestEndpoint);
            request.Method = "GET";
            request.Headers.Add("Authorization", authenticate());
            request.AllowAutoRedirect = false;

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode == HttpStatusCode.TemporaryRedirect || response.StatusCode == HttpStatusCode.Redirect)
                {
                    string serverRestEndpoint2 = response.Headers.Get("location");
                    HttpWebRequest request2 = (HttpWebRequest)WebRequest.Create(serverRestEndpoint2);
                    request2.Method = "GET";
                    request2.Headers.Add("Authorization", authenticate());
                    request2.AllowAutoRedirect = false;
                    using (HttpWebResponse response2 = (HttpWebResponse)request2.GetResponse())
                    {
                        using (Stream dataStream2 = response2.GetResponseStream())
                        {
                            using (StreamReader reader = new(dataStream2))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            return null;
        }

        #endregion


    }
}
