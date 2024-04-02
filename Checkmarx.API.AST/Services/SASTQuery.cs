using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Services
{
    public partial class SASTQuery
    {
        private string _baseUrl;
        private System.Net.Http.HttpClient _httpClient;

        public SASTQuery(string baseUrl, System.Net.Http.HttpClient httpClient)
        {
            _baseUrl = baseUrl;
            _httpClient = httpClient;
        }

        public IEnumerable<Query> GetQueries()
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries";
            WebRequest request = WebRequest.Create(serverRestEndpoint);
            request.Method = "GET";
            request.Headers.Add("Authorization", _httpClient.DefaultRequestHeaders.Authorization.Parameter);

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream dataStream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                            return JsonConvert.DeserializeObject<IEnumerable<Query>>(responseFromServer);//["results"].ToObject<IEnumerable<dynamic>>();
                        }
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    if (we.Status == WebExceptionStatus.ProtocolError)
                        throw new WebException($"Server response HTTP status: {((HttpWebResponse)we.Response).StatusCode} ({(int)((HttpWebResponse)we.Response).StatusCode})");

                    using (Stream dataStream = we.Response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                        }
                    }
                }
                throw we;
            }

        }

        public IEnumerable<Query> GetQueriesForProject(Guid projId)
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries?projectId={projId}";
            WebRequest request = WebRequest.Create(serverRestEndpoint);
            request.Method = "GET";
            request.Headers.Add("Authorization", _httpClient.DefaultRequestHeaders.Authorization.Parameter);

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream dataStream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                            return JsonConvert.DeserializeObject<IEnumerable<Query>>(responseFromServer);//["results"].ToObject<IEnumerable<dynamic>>();
                        }
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    if (we.Status == WebExceptionStatus.ProtocolError)
                        throw new WebException($"Server response HTTP status: {((HttpWebResponse)we.Response).StatusCode} ({(int)((HttpWebResponse)we.Response).StatusCode})");

                    using (Stream dataStream = we.Response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                        }
                    }
                }
                throw we;
            }

        }

        public Query GetQueryForProject(Guid projId, string queryPath, bool tenantLevel)
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries/{(tenantLevel ? "Corp" : projId)}/{System.Web.HttpUtility.UrlEncode(queryPath)}";
            WebRequest request = WebRequest.Create(serverRestEndpoint);
            request.Method = "GET";
            request.Headers.Add("Authorization", _httpClient.DefaultRequestHeaders.Authorization.Parameter);

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream dataStream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                            return JsonConvert.DeserializeObject<Query>(responseFromServer);
                        }
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    if (we.Status == WebExceptionStatus.ProtocolError)
                    {
                        throw new WebException($"Server response HTTP status: {((HttpWebResponse)we.Response).StatusCode} ({(int)((HttpWebResponse)we.Response).StatusCode})");
                    }
                    using (Stream dataStream = we.Response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                        }
                    }
                }
                throw we;
            }

        }

        public dynamic GetCxLevelQuery(string queryPath)
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries/Cx/{System.Web.HttpUtility.UrlEncode(queryPath)}";
            WebRequest request = WebRequest.Create(serverRestEndpoint);
            request.Method = "GET";
            request.Headers.Add("Authorization", _httpClient.DefaultRequestHeaders.Authorization.Parameter);

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream dataStream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                            return JsonConvert.DeserializeObject<Query>(responseFromServer);
                        }
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    if (we.Status == WebExceptionStatus.ProtocolError)
                    {
                        throw new WebException($"Server response HTTP status: {((HttpWebResponse)we.Response).StatusCode} ({(int)((HttpWebResponse)we.Response).StatusCode})");
                    }
                    using (Stream dataStream = we.Response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                        }
                    }
                }
                throw we;
            }

        }

        public void DeleteProjectQuery(Guid projId, string queryPath)
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries/{projId}/{System.Web.HttpUtility.UrlEncode(queryPath)}";
            WebRequest request = WebRequest.Create(serverRestEndpoint);
            request.Method = "DELETE";
            request.Headers.Add("Authorization", _httpClient.DefaultRequestHeaders.Authorization.Parameter);


            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream dataStream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            //string responseFromServer = reader.ReadToEnd();
                            //return JsonConvert.DeserializeObject<dynamic>(responseFromServer);
                            return;
                        }
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    if (we.Status == WebExceptionStatus.ProtocolError)
                    {
                        throw new WebException($"Server response HTTP status: {((HttpWebResponse)we.Response).StatusCode} ({(int)((HttpWebResponse)we.Response).StatusCode})");
                    }
                    using (Stream dataStream = we.Response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                        }
                    }
                }
                throw we;
            }

        }

        public void DeleteCorpQuery(string queryPath)
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries/corp/{System.Web.HttpUtility.UrlEncode(queryPath)}";
            WebRequest request = WebRequest.Create(serverRestEndpoint);
            request.Method = "DELETE";
            request.Headers.Add("Authorization", _httpClient.DefaultRequestHeaders.Authorization.Parameter);

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream dataStream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            //string responseFromServer = reader.ReadToEnd();
                            //return JsonConvert.DeserializeObject<dynamic>(responseFromServer);
                            return;
                        }
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    if (we.Status == WebExceptionStatus.ProtocolError)
                    {
                        throw new WebException($"Server response HTTP status: {((HttpWebResponse)we.Response).StatusCode} ({(int)((HttpWebResponse)we.Response).StatusCode})");
                    }
                    using (Stream dataStream = we.Response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                        }
                    }
                }
                throw we;
            }

        }

        public void SaveProjectQuery(string projId, string aname, string aqueryPath, string asource)
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries/{projId}";
            WebRequest request = WebRequest.Create(serverRestEndpoint);
            request.Method = "PUT";
            request.Headers.Add("Authorization", _httpClient.DefaultRequestHeaders.Authorization.Parameter);

            try
            {

                var payload = new List<dynamic>() {
                    new {
                    name = aname,
                    path = aqueryPath,
                    source = asource
                }
                };
                string json = JsonConvert.SerializeObject(payload);
                byte[] byteArray = Encoding.UTF8.GetBytes(json);

                request.ContentLength = byteArray.Length;
                using (Stream dataStream = request.GetRequestStream())
                {
                    dataStream.Write(byteArray, 0, byteArray.Length);
                }

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream dataStream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            //string responseFromServer = reader.ReadToEnd();
                            //return JsonConvert.DeserializeObject<dynamic>(responseFromServer);
                            return;
                        }
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    if (we.Status == WebExceptionStatus.ProtocolError)
                    {
                        throw new WebException($"Server response HTTP status: {((HttpWebResponse)we.Response).StatusCode} ({(int)((HttpWebResponse)we.Response).StatusCode})");
                    }
                    using (Stream dataStream = we.Response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                        }
                    }
                }
                throw we;
            }

        }

        public void SaveCorpQuery(string aname, string aqueryPath, string asource)
        {
            string serverRestEndpoint = $"{_baseUrl}api/cx-audit/queries/corp";
            WebRequest request = WebRequest.Create(serverRestEndpoint);
            request.Method = "PUT";
            request.Headers.Add("Authorization", _httpClient.DefaultRequestHeaders.Authorization.Parameter);

            try
            {

                var payload = new List<dynamic>() {
                    new {
                    name = aname,
                    path = aqueryPath,
                    source = asource
                }
                };
                string json = JsonConvert.SerializeObject(payload);
                byte[] byteArray = Encoding.UTF8.GetBytes(json);

                request.ContentLength = byteArray.Length;
                using (Stream dataStream = request.GetRequestStream())
                {
                    dataStream.Write(byteArray, 0, byteArray.Length);
                }

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream dataStream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            //string responseFromServer = reader.ReadToEnd();
                            //return JsonConvert.DeserializeObject<dynamic>(responseFromServer);
                            return;
                        }
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    if (we.Status == WebExceptionStatus.ProtocolError)
                    {
                        throw new WebException($"Server response HTTP status: {((HttpWebResponse)we.Response).StatusCode} ({(int)((HttpWebResponse)we.Response).StatusCode})");
                    }
                    using (Stream dataStream = we.Response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(dataStream))
                        {
                            string responseFromServer = reader.ReadToEnd();
                        }
                    }
                }
                throw we;
            }

        }


        public partial class Query
        {
            [Newtonsoft.Json.JsonProperty("id", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string? Id { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("name", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string? Name { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("group", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string? Group { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("level", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string? Level { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("lang", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string? Lang { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("path", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string? Path { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("isExecutable", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public bool IsExecutable { get; set; } = default!;

            [Newtonsoft.Json.JsonProperty("source", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
            public string? Source { get; set; } = default!;

            private System.Collections.Generic.IDictionary<string, object>? _additionalProperties;

            [Newtonsoft.Json.JsonExtensionData]
            public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
            {
                get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
                set { _additionalProperties = value; }
            }

            public string ToJson()
            {

                return Newtonsoft.Json.JsonConvert.SerializeObject(this, new Newtonsoft.Json.JsonSerializerSettings());

            }
            public static Query FromJson(string data)
            {

                return Newtonsoft.Json.JsonConvert.DeserializeObject<Query>(data, new Newtonsoft.Json.JsonSerializerSettings());

            }

        }
    }
}
