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
    public struct CxOneConnection
    {
        public Uri CxOneServer;
        public Uri AccessControlServer;
        public string Tenant;
        public string ApiKey;
    }

    public class ASTClient
    {
        public Uri AccessControlServer { get; private set; }
        public Uri ASTServer { get; private set; }
        public string Tenant { get; }
        public string KeyApi { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }

        private readonly HttpClient _httpClient = new HttpClient();

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
                if (Connected && _projects  == null)
                    _projects = new Projects($"{ASTServer.AbsoluteUri}api/projects", _httpClient);

                return _projects;
            }
        }

        private FeatureFlags _featureFlags;
        public FeatureFlags FeatureFlags
        {
            get
            {
                if (Connected && _featureFlags  == null)
                    _featureFlags = new FeatureFlags(ASTServer, _httpClient);

                return _featureFlags;
            }
        }

        private Lists _lists;
        public Lists Lists
        {
            get
            {
                if (Connected && _lists  == null)
                    _lists = new Lists(ASTServer, _httpClient);

                return _lists;
            }
        }

        private Scans _scans;
        public Scans Scans
        {
            get
            {
                if (Connected && _scans  == null)
                    _scans = new Scans($"{ASTServer.AbsoluteUri}api/scans", _httpClient);

                return _scans;
            }
        }

        private Reports _reports;
        public Reports Reports
        {
            get
            {
                if (Connected && _reports  == null)
                    _reports = new Reports($"{ASTServer.AbsoluteUri}api/reports", _httpClient);

                return _reports;
            }
        }

        private Requests _requests;
        public Requests Requests
        {
            get
            {
                if (Connected && _requests  == null)
                    _requests = new Requests(ASTServer, _httpClient);

                return _requests;
            }
        }


        private SASTMetadata _SASTMetadata;
        public SASTMetadata SASTMetadata
        {
            get
            {
                if (Connected && _SASTMetadata  == null)
                    _SASTMetadata = new SASTMetadata($"{ASTServer.AbsoluteUri}api/sast-metadata", _httpClient);

                return _SASTMetadata;
            }
        }

        private Applications _applications;
        public Applications Applications
        {
            get
            {
                if (Connected && _applications  == null)
                    _applications = new Applications($"{ASTServer.AbsoluteUri}api/applications", _httpClient);

                return _applications;
            }
        }


        private SASTResults _SASTResults;

        /// <summary>
        /// Engine SAST results
        /// </summary>
        public SASTResults SASTResults
        {
            get
            {
                if (Connected && _SASTResults  == null)
                    _SASTResults = new SASTResults(ASTServer, _httpClient);

                return _SASTResults;
            }
        }


        private SASTResultsPredicates _SASTResultsPredicates;

        /// <summary>
        /// Engine SAST results Predicates
        /// </summary>
        public SASTResultsPredicates SASTResultsPredicates
        {
            get
            {
                if (Connected && _SASTResultsPredicates  == null)
                    _SASTResultsPredicates = new SASTResultsPredicates(ASTServer, _httpClient);



                return _SASTResultsPredicates;
            }
        }


        private KicsResults _kicsResults;

        /// <summary>
        /// KICS results
        /// </summary>
        public KicsResults KicsResults
        {
            get
            {
                if (Connected && _kicsResults  == null)
                    _kicsResults = new KicsResults($"{ASTServer.AbsoluteUri}api/kics-results", _httpClient);



                return _kicsResults;
            }
        }

        private KICSResultsPredicates _kicsResultsPredicates;

        /// <summary>
        /// KICS marking/predicates
        /// </summary>
        public KICSResultsPredicates KicsResultsPredicates
        {
            get
            {
                if (Connected && _kicsResultsPredicates  == null)
                    _kicsResultsPredicates = new KICSResultsPredicates(ASTServer, _httpClient);



                return _kicsResultsPredicates;
            }
        }

        private CxOneSCA _cxOneSCA;

        /// <summary>
        /// SCA API
        /// </summary>
        public CxOneSCA SCA
        {
            get
            {
                if (Connected && _cxOneSCA  == null)
                    _cxOneSCA = new CxOneSCA(ASTServer, _httpClient);



                return _cxOneSCA;
            }
        }

        private ScannersResults _scannersResults;

        /// <summary>
        /// Engine Scanners results
        /// </summary>
        public ScannersResults ScannersResults
        {
            get
            {
                if (Connected && _scannersResults  == null)
                    _scannersResults = new ScannersResults($"{ASTServer.AbsoluteUri}api/results", _httpClient);



                return _scannersResults;
            }
        }


        private ResultsSummary _resultsSummary;

        /// <summary>
        /// Engine Results Summary
        /// </summary>
        public ResultsSummary ResultsSummary
        {
            get
            {
                if (Connected && _resultsSummary  == null)
                    _resultsSummary = new ResultsSummary($"{ASTServer.AbsoluteUri}api/scan-summary", _httpClient);



                return _resultsSummary;
            }
        }

        private ResultsOverview _resultsOverview;
        public ResultsOverview ResultsOverview
        {
            get
            {
                if (Connected && _resultsOverview  == null)
                    _resultsOverview = new ResultsOverview($"{ASTServer.AbsoluteUri}api/results-overview", _httpClient);



                return _resultsOverview;
            }
        }


        private Configuration _configuration;

        /// <summary>
        /// Configurations
        /// </summary>
        public Configuration Configuration
        {
            get
            {
                if (Connected && _configuration  == null)
                    _configuration = new Configuration($"{ASTServer.AbsoluteUri}api/configuration", _httpClient);

                return _configuration;
            }
        }

        private Repostore _repostore;

        public Repostore Repostore
        {
            get
            {
                if (Connected && _repostore  == null)
                    _repostore = new Repostore($"{ASTServer.AbsoluteUri}api/repostore/code", _httpClient);



                return _repostore;
            }
        }

        private Uploads _uploads;

        public Uploads Uploads
        {
            get
            {
                if (Connected && _uploads  == null)
                    _uploads = new Uploads($"{ASTServer.AbsoluteUri}api/uploads", _httpClient);



                return _uploads;
            }
        }

        private PresetManagement _presetManagement;

        public PresetManagement PresetManagement
        {
            get
            {
                if (Connected && _presetManagement  == null)
                    _presetManagement = new PresetManagement($"{ASTServer.AbsoluteUri}api/presets", _httpClient);



                return _presetManagement;
            }
        }

        private SASTQuery _sastQuery;

        public SASTQuery SASTQuery
        {
            get
            {
                if (Connected && _sastQuery  == null)
                    _sastQuery = new SASTQuery(ASTServer.AbsoluteUri, _httpClient);

                return _sastQuery;
            }
        }


        private SASTQueriesAudit _sastQueriesAudit;

        public SASTQueriesAudit SASTQueriesAudit
        {
            get
            {
                if (Connected && _sastQueriesAudit  == null)
                    _sastQueriesAudit = new SASTQueriesAudit($"{ASTServer.AbsoluteUri}api/cx-audit", _httpClient);



                return _sastQueriesAudit;
            }
        }

        private Logs _logs;

        /// <summary>
        /// Log Services
        /// </summary>
        public Logs Logs
        {
            get
            {
                if (Connected && _logs  == null)
                    _logs = new Logs(ASTServer, _httpClient);

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
                if (_httpClient == null || (_bearerValidTo - DateTime.UtcNow).TotalMinutes < 5)
                {
                    var token = authenticate();
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    _httpClient.DefaultRequestHeaders.ConnectionClose = false; // Explicitly ask to keep connection alive
                    _bearerValidTo = DateTime.UtcNow.AddSeconds(_bearerExpiresIn - 300);
                }
                return true;
            }
        }

        private void checkConnection()
        {
            if (!Connected)
                throw new NotSupportedException();
        }

        public string authenticate()
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

        public ASTClient(CxOneConnection connectionSettings)
            : this(connectionSettings.CxOneServer, connectionSettings.AccessControlServer, connectionSettings.Tenant, connectionSettings.ApiKey) { }

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

        private Services.Applications.ApplicationsCollection getAllApplications(int limit = 20)
        {
            var listApplications = Applications.GetListOfApplicationsAsync(limit).Result;
            if (listApplications.TotalCount > limit)
            {
                var offset = limit;
                bool cont = true;
                do
                {
                    var next = Applications.GetListOfApplicationsAsync(limit, offset).Result;
                    if (next.Applications.Any())
                    {
                        next.Applications.ToList().ForEach(o => listApplications.Applications.Add(o));
                        offset += limit;

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

        public ICollection<Services.Projects.Project> GetAllProjectsDetails(int startAt = 0, int limit = 500)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            var result = new List<Services.Projects.Project>();

            while (true)
            {
                var resultPage = Projects.GetListOfProjectsAsync(limit: limit, offset: startAt).Result;

                if (resultPage.Projects != null)
                    result.AddRange(resultPage.Projects);

                startAt += limit;

                if (resultPage.TotalCount == 0 || resultPage.TotalCount == result.Count)
                    return result;
            }
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

        public IEnumerable<ResultsSummary> GetResultsSummaryById(Guid scanId)
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

        private IEnumerable<Scan> getAllScans(Guid projectId, string branch = null, int itemsPerPage = 1000, int startAt = 0)
        {
            while (true)
            {
                var result = Scans.GetListOfScansAsync(projectId, limit: itemsPerPage, offset: startAt, branch: branch).Result;

                foreach (var scan in result.Scans)
                {
                    yield return scan;
                }

                startAt += itemsPerPage;

                if (result.Scans.Count == 0)
                    yield break;
            }
        }

        public Scan GetLastScan(Guid projectId, bool fullScanOnly = false, bool completed = true, string branch = null, ScanTypeEnum scanType = ScanTypeEnum.sast, DateTime? maxScanDate = null)
        {
            if (!fullScanOnly && !maxScanDate.HasValue)
            {
                var scanStatus = completed ? CompletedStage : null;

                var scans = this.Projects.GetProjectLastScan([projectId], scan_status: scanStatus, branch: branch, engine: scanType.ToString()).Result;

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

            var scans = getAllScans(projectId, branch);

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

        public ScanDetails GetScanDetails(Scan scan)
        {
            if (scan == null)
                throw new ArgumentNullException($"No scan found.");

            return new ScanDetails(this, scan);
        }

        public ReportResults GetCxOneScanJsonReport(Guid projectId, Guid scanId, double secondsBetweenPolls = 0.5)
        {
            TimeSpan poolInverval = TimeSpan.FromSeconds(secondsBetweenPolls);

            ScanReportCreateInput sc = new ScanReportCreateInput
            {
                ReportName = BaseReportCreateInputReportName.ScanReport,
                ReportType = BaseReportCreateInputReportType.Ui,
                FileFormat = BaseReportCreateInputFileFormat.Json,
                Data = new Data
                {
                    ProjectId = projectId,
                    ScanId = scanId
                }
            };

            ReportCreateOutput createReportOutut = Reports.CreateReportAsync(sc).Result;

            if (createReportOutut == null)
                throw new NotSupportedException();

            var createReportId = createReportOutut.ReportId;

            if (createReportId == Guid.Empty)
                throw new Exception($"Error getting Report of Scan {scanId}");

            Guid reportId = createReportId;
            string reportStatus = "Requested";
            string pastReportStatus = reportStatus;
            double aprox_seconds_passed = 0.0;
            Report statusResponse = null;

            do
            {
                System.Threading.Thread.Sleep(poolInverval);
                aprox_seconds_passed += 1.020;

                statusResponse = Reports.GetReportAsync(reportId, true).Result;
                reportId = statusResponse.ReportId;
                reportStatus = statusResponse.Status.ToString();

                if (pastReportStatus != reportStatus)
                {
                    pastReportStatus = reportStatus;
                }

                if (aprox_seconds_passed > 60)
                {
                    throw new TimeoutException("AST Scan json report for project {0} is taking a long time! Try again later.");
                }

                if (reportStatus == "Failed")
                {

                    throw new Exception("AST Scan API says it could not generate a json report for project {0}. You may want to try again later.");
                }

            } while (reportStatus != "Completed");

            var reportString = Reports.DownloadScanReportJsonUrl(statusResponse.Url).Result;

            return JsonConvert.DeserializeObject<ReportResults>(reportString);
        }

        public IEnumerable<SASTResult> GetSASTScanResultsById(Guid scanId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));


            while (true)
            {
                Services.SASTResults.SASTResultsResponse response = SASTResults.GetSASTResultsByScanAsync(scanId, startAt, limit).Result;

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

            ScanInput scanInput = new ScanInput
            {
                Project = new Services.Scans.Project() { Id = projectId },
                Type = ScanInputType.Git,
                Handler = new Git()
                {
                    Branch = branch,
                    RepoUrl = repoUrl
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
                    Id = projectId
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

                Scans.DeleteScanAsync(scanId).Wait();
            }
        }

        public void CancelScan(Guid scanId)
        {
            Scans.CancelScanAsync(scanId, new Body { Status = Status.Canceled.ToString() }).Wait();
        }

        #endregion

        #region Results

        public bool MarkSASTResult(Guid projectId, SASTResult result, IEnumerable<PredicateWithCommentJSON> history, bool updateSeverity = true, bool updateState = true, bool updateComment = true)
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
        /// Mark IaC, KICS results.
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        /// <exception cref="NotSupportedException"></exception>
        public bool MarkKICSResult(Guid projectId, string similarityId, Services.KicsResults.SeverityEnum severity, KicsStateEnum state, string comment = null)
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

        public void MarkSCAVulnerability(Guid projectId, Vulnerability vulnerabilityRisk, VulnerabilityStatus vulnerabilityStatus, string message)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (vulnerabilityRisk == null)
                throw new ArgumentNullException(nameof(vulnerabilityRisk));

            if (string.IsNullOrEmpty(message))
                throw new ArgumentNullException(nameof(message));

            SCA.UpdateResultState(new PackageInfo
            {
                PackageManager= vulnerabilityRisk.PackageManager,
                PackageName = vulnerabilityRisk.PackageName,
                PackageVersion = vulnerabilityRisk.PackageVersion,
                VulnerabilityId = vulnerabilityRisk.Id,
                ProjectIds = [projectId],
                Actions = [
                new ActionType
                {
                    Type = ActionTypeEnum.ChangeState,
                    Value = vulnerabilityStatus,
                    Comment = message
                }
            ],
            }).Wait();
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

        public Dictionary<string, ScanParameter> GetScanConfigurations(Scan scan)
        {
            if(scan == null)
                throw new ArgumentNullException(nameof(scan));

            return GetScanConfigurations(scan.ProjectId, scan.Id);
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

        /// <summary>
        /// Get the last note of the history of comments of the SAST finding.
        /// </summary>
        /// <param name="similarityID"></param>
        /// <param name="projects_ids"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public string GetLastSASTNote(long similarityID, params Guid[] projects_ids)
        {
            if (!projects_ids.Any())
                throw new ArgumentOutOfRangeException(nameof(projects_ids));

            var lastState = SASTResultsPredicates.GetLatestPredicatesBySimilarityIDAsync(similarityID, projects_ids).Result;
            return lastState.LatestPredicatePerProject?.FirstOrDefault()?.Comment;
        }

        #endregion


    }
}
