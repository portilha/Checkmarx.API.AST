using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;

namespace Checkmarx.API.AST
{
    public class ASTClient
    {
        public Uri AcessControlServer { get; private set; }
        public Uri ASTServer { get; private set; }
        public string Tenant { get; }
        public string KeyApi { get; set; }

        private Projects _projects;
        public Projects Projects
        {
            get {
                if (_projects == null && Connected)
                    _projects = new Projects(_httpClient)
                    {
                        BaseUrl = $"{ASTServer.AbsoluteUri}api/projects"
                    };

                return _projects;  
            }
        }

        private Applications _applications;
        public Applications Applications
        {
            get
            {
                if (_applications == null && Connected)
                    _applications = new Applications(_httpClient)
                    {
                        BaseUrl = $"{ASTServer.AbsoluteUri}api/applications"
                    };

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

        private readonly HttpClient _httpClient = new HttpClient();

        private DateTime _bearerValidTo;

        public bool Connected
        {
            get
            {
                if (_httpClient == null || (_bearerValidTo - DateTime.UtcNow).TotalMinutes < 5)
                {
                    var token = Autenticate();
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    _bearerValidTo = DateTime.UtcNow.AddHours(1);
                }
                return true;
            }
        }

        private void checkConnection()
        {
            if (!Connected)
                throw new NotSupportedException();
        }

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

        private string Autenticate()
        {
            var identityURL = $"{AcessControlServer.AbsoluteUri}auth/realms/{Tenant}/protocol/openid-connect/token";
            var kv = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "client_id", "ast-app" },
                { "refresh_token", $"{KeyApi}" }
            };

            var req = new HttpRequestMessage(HttpMethod.Post, identityURL) { Content = new FormUrlEncodedContent(kv) };
            var response = _httpClient.SendAsync(req).Result;
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                JObject accessToken = JsonConvert.DeserializeObject<JObject>(response.Content.ReadAsStringAsync().Result);
                string authToken = ((JProperty)accessToken.First).Value.ToString();
                return authToken;
            }
            throw new Exception(response.Content.ReadAsStringAsync().Result);
        }

        public ProjectsCollection GetAllProjectsDetails(bool showAlsoDeletedProjects = false)
        {
            checkConnection();

            return Projects.GetListOfProjectsAsync().Result;
        }



        public IEnumerable<Scan> GetAllSASTScans(Guid projectId)
        {
            return GetScans(projectId, true, ScanRetrieveKind.All);
        }

        public Scan GetLastScan(Guid projectId)
        {
            var scan = GetScans(projectId, true, ScanRetrieveKind.Last);
            return scan.FirstOrDefault();
        }

        public Scan GetLockedScan(Guid projectId)
        {
            return GetScans(projectId, true, ScanRetrieveKind.Locked).FirstOrDefault();
        }

        public IEnumerable<Scan> GetScans(Guid projectId, bool finished,
            ScanRetrieveKind scanKind = ScanRetrieveKind.All, string version = null)
        {
            //checkConnection();

            //IQueryable<CxDataRepository.Scan> scans = SASTResults. _oDataScans.Where(x => x.ProjectId == projectId);

            //if (version != null)
            //    scans = scans.Where(x => version.StartsWith(x.ProductVersion));

            //switch (scanKind)
            //{
            //    case ScanRetrieveKind.First:
            //        scans = scans.Take(1);
            //        break;
            //    case ScanRetrieveKind.Last:
            //        scans = scans.Skip(Math.Max(0, scans.Count() - 1));
            //        break;

            //    case ScanRetrieveKind.Locked:
            //        scans = scans.Where(x => x.IsLocked);
            //        break;
            //    case ScanRetrieveKind.All:
            //        break;
            //}

            //foreach (var scan in scans)
            //{
            //    if (finished && scan.ScanType == 3)
            //        continue;

            //    yield return ConvertScanFromOData(scan);
            //}

            return new List<Scan>();
        }
    }
}
