using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Checkmarx.API.AST
{
    public class ASTClient
    {
        public Uri Server { get; set; }

        public string Tenant { get; }

        public string KeyApi { get; set; }


        private Projects _projects;
        public Projects Projects
        {
            get { 
                if(_projects == null && Connected)
                    _projects = new Projects(_httpClient);

                return _projects;  
            }
        }


        private readonly HttpClient _httpClient = new HttpClient();

        public bool Connected
        {
            get
            {
                return Autenticate() != null;
            }
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="server">
        /// URL
        /// https://eu.iam.checkmarx.net
        /// US Environment - https://ast.checkmarx.net/
        /// EU Environment - https://eu.ast.checkmarx.net/
        /// </param>
        /// <param name="tenant"></param>
        /// <param name="apiKey"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public ASTClient(Uri server, string tenant, string apiKey)
        {
            if (server == null) throw new ArgumentNullException(nameof(server));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentNullException(nameof(apiKey));

            Server = server;
            Tenant = tenant;
            KeyApi = apiKey;
        }

        private string Autenticate()
        {
            var identityURL = $"{Server.AbsoluteUri}/auth/realms/{Tenant}/protocol/openid-connect/token";
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

    }
}
