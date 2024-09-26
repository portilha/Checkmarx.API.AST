using Checkmarx.API.AST.Services.Reports;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Checkmarx.API.AST.Models.Report;
using System.Threading;
using static Checkmarx.API.AST.ASTClient;

namespace Checkmarx.API.AST.Services
{


    public enum ActionTypeEnum
    {
        [System.Runtime.Serialization.EnumMember(Value = @"ChangeState")]
        ChangeState
    }

    public enum VulnerabilityStatus
    {
        [System.Runtime.Serialization.EnumMember(Value = @"Confirmed")]
        Confirmed,
        [System.Runtime.Serialization.EnumMember(Value = @"NotExploitable")]
        NotExploitable,
        [System.Runtime.Serialization.EnumMember(Value = @"ProposedNotExploitable")]
        ProposedNotExploitable,
        [System.Runtime.Serialization.EnumMember(Value = @"ToVerify")]
        ToVerify,
        [System.Runtime.Serialization.EnumMember(Value = @"Urgent")]
        Urgent
    }

    public class ExportStatusDetails
    {
        const string Completed = "Completed";
        const string Failed = "Failed";

        [JsonProperty("exportId")]
        public Guid ExportId { get; set; }

        [JsonProperty("exportStatus")]
        public string ExportStatus { get; set; }

        [JsonProperty("fileUrl")]
        public string FileUrl { get; set; }

        public bool IsCompleted()
        {
            return ExportStatus == Completed;
        }

        public bool IsFailed()
        {
            return ExportStatus == Failed;
        }
    }

    public class ExportDataResponse
    {
        [JsonProperty("exportId")]
        public Guid ExportId { get; set; }
    }

    public class ScanData
    {
        [JsonProperty("ScanId", Required = Newtonsoft.Json.Required.Always)]
        public Guid ScanId { get; set; }

        [JsonProperty("FileFormat", Required = Newtonsoft.Json.Required.Always)]
        public string FileFormat { get; set; }

        [JsonProperty("ExportParameters")]
        public ExportParameters ExportParameters { get; set; }
    }

    public class FileFormatEndpoint
    {
        [JsonProperty("route")]
        public string Route { get; set; }

        [JsonProperty("fileFormats")]
        public List<string> FileFormats { get; set; }
    }


    public class ExportParameters
    {
        /// <summary>
        /// If you would like to exclude all development and test dependencies from the SBOM, set this flag as true.. Default: false
        /// </summary>
        [JsonProperty("hideDevAndTestDependencies")]
        public bool HideDevAndTestDependencies { get; set; }

        /// <summary>
        /// If you would like to exclude all licenses that aren't marked as "Effective" from the SBOM, set this flag as true. Default: false
        /// </summary>
        [JsonProperty("showOnlyEffectiveLicenses")]
        public bool ShowOnlyEffectiveLicenses { get; set; }

        /// <summary>
        /// Relevant only for scan reports
        /// </summary>
        [JsonProperty("excludePackages")]
        public bool ExcludePackages { get; set; }

        /// <summary>
        /// Relevant only for scan reports
        /// </summary>
        [JsonProperty("excludeLicenses")]
        public bool ExcludeLicenses { get; set; }

        /// <summary>
        /// Relevant only for scan reports
        /// </summary>
        [JsonProperty("excludeVulnerabilities")]
        public bool ExcludeVulnerabilities { get; set; }

        /// <summary>
        /// Relevant only for scan reports
        /// </summary>
        [JsonProperty("excludePolicies")]
        public bool ExcludePolicies { get; set; }


        /// <summary>
        /// Comma separated list of paths to manifest files that will be remediated. Paths are relative to the repo folder
        /// </summary>
        /// <remarks>Relevant only for RemediatedPackagesJson reports</remarks>
        [JsonProperty("filePaths")]
        public List<string> FilePaths { get; set; }

        /// <summary>
        /// If set as true, the output will always be returned in a zip archive. If false (default), then if there is a single filepath the output will be returned as a json.
        /// </summary>
        /// <remarks>If there are multiple filepaths, then the output is always returned as a zip archive, even if this parameter is set as false.</remarks>
        [JsonProperty("compressedOutput")]
        public bool CompressedOutput { get; set; }
    }

    /// <summary>
    /// Based on the documentation, https://checkmarx.com/resource/documents/en/34965-145615-checkmarx-sca--rest--api---export-service.html
    /// </summary>
    public partial class Requests
    {
        private string _baseUrl = "/api/sca/export";
        private System.Net.Http.HttpClient _httpClient;
        private System.Lazy<Newtonsoft.Json.JsonSerializerSettings> _settings;

        public Requests(Uri aSTServer, System.Net.Http.HttpClient httpClient)
        {
            BaseUrl = $"{aSTServer.AbsoluteUri}api/sca/export";
            _httpClient = httpClient;
            _settings = new System.Lazy<Newtonsoft.Json.JsonSerializerSettings>(CreateSerializerSettings);
            ReadResponseAsString = true;
        }

        private Newtonsoft.Json.JsonSerializerSettings CreateSerializerSettings()
        {
            var settings = new Newtonsoft.Json.JsonSerializerSettings();
            UpdateJsonSerializerSettings(settings);
            return settings;
        }

        public string BaseUrl
        {
            get { return _baseUrl; }
            set { _baseUrl = value; }
        }

        protected Newtonsoft.Json.JsonSerializerSettings JsonSerializerSettings { get { return _settings.Value; } }

        partial void UpdateJsonSerializerSettings(Newtonsoft.Json.JsonSerializerSettings settings);

        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, string url);
        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, System.Text.StringBuilder urlBuilder);
        partial void ProcessResponse(System.Net.Http.HttpClient client, System.Net.Http.HttpResponseMessage response);


        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        /// <summary>
        /// Create a report
        /// </summary>
        /// <returns>Accepted</returns>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        internal virtual async System.Threading.Tasks.Task<ExportDataResponse> CreateReportAsync(ScanData body, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            if (body == null)
                throw new System.ArgumentNullException("body");

            var urlBuilder_ = new System.Text.StringBuilder();
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "").Append("/requests");

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    var content_ = new System.Net.Http.StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(body, _settings.Value));
                    content_.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json; version=1.0");
                    request_.Content = content_;
                    request_.Method = new System.Net.Http.HttpMethod("POST");
                    request_.Headers.Accept.Add(System.Net.Http.Headers.MediaTypeWithQualityHeaderValue.Parse("application/json"));

                    PrepareRequest(client_, request_, urlBuilder_);

                    var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url_, System.UriKind.RelativeOrAbsolute);

                    PrepareRequest(client_, request_, url_);

                    var response_ = await _retryPolicy.ExecuteAsync(() => client_.SendAsync(CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);
                    var disposeResponse_ = true;
                    try
                    {
                        var headers_ = System.Linq.Enumerable.ToDictionary(response_.Headers, h_ => h_.Key, h_ => h_.Value);
                        if (response_.Content != null && response_.Content.Headers != null)
                        {
                            foreach (var item_ in response_.Content.Headers)
                                headers_[item_.Key] = item_.Value;
                        }

                        ProcessResponse(client_, response_);

                        var status_ = (int)response_.StatusCode;
                        if (status_ == 202)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<ExportDataResponse>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            return objectResponse_.Object;
                        }
                        else
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("The HTTP status code of the response was not expected (" + status_ + ").", status_, responseData_, headers_, null);
                        }
                    }
                    finally
                    {
                        if (disposeResponse_)
                            response_.Dispose();
                    }
                }
            }
            finally
            {
                if (disposeClient_)
                    client_.Dispose();
            }
        }

        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        /// <summary>
        /// Get a report status
        /// </summary>
        /// <returns>OK</returns>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        internal virtual async System.Threading.Tasks.Task<ExportStatusDetails> GetReportStatusAsync(System.Guid exportId, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            if (exportId == Guid.Empty)
                throw new System.ArgumentNullException(nameof(exportId));

            var urlBuilder_ = new System.Text.StringBuilder();
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "").Append("/requests?exportId={exportId}");
            urlBuilder_.Replace("{exportId}", System.Uri.EscapeDataString(ConvertToString(exportId, System.Globalization.CultureInfo.InvariantCulture)));

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    request_.Method = new System.Net.Http.HttpMethod("GET");
                    request_.Headers.Accept.Add(System.Net.Http.Headers.MediaTypeWithQualityHeaderValue.Parse("application/json"));

                    PrepareRequest(client_, request_, urlBuilder_);

                    var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url_, System.UriKind.RelativeOrAbsolute);

                    PrepareRequest(client_, request_, url_);

                    var response_ = await _retryPolicy.ExecuteAsync(() => client_.SendAsync(CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);
                    var disposeResponse_ = true;
                    try
                    {
                        var headers_ = System.Linq.Enumerable.ToDictionary(response_.Headers, h_ => h_.Key, h_ => h_.Value);
                        if (response_.Content != null && response_.Content.Headers != null)
                        {
                            foreach (var item_ in response_.Content.Headers)
                                headers_[item_.Key] = item_.Value;
                        }

                        ProcessResponse(client_, response_);

                        var status_ = (int)response_.StatusCode;
                        if (status_ == 200)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<ExportStatusDetails>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            return objectResponse_.Object;
                        }
                        else
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("The HTTP status code of the response was not expected (" + status_ + ").", status_, responseData_, headers_, null);
                        }
                    }
                    finally
                    {
                        if (disposeResponse_)
                            response_.Dispose();
                    }
                }
            }
            finally
            {
                if (disposeClient_)
                    client_.Dispose();
            }
        }

        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        /// <summary>
        /// Download a report
        /// </summary>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        internal virtual async System.Threading.Tasks.Task<string> DownloadScanReport(string url, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            if (string.IsNullOrEmpty(url))
                throw new System.ArgumentNullException("exportId");

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    request_.Method = new System.Net.Http.HttpMethod("GET");

                    PrepareRequest(client_, request_, url);

                    //var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url, System.UriKind.RelativeOrAbsolute);

                    PrepareRequest(client_, request_, url);

                    System.Net.Http.HttpResponseMessage response_ = null;
                    var disposeResponse_ = true;
                    try
                    {
                        response_ = await client_.SendAsync(CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

                        var headers_ = System.Linq.Enumerable.ToDictionary(response_.Headers, h_ => h_.Key, h_ => h_.Value);
                        if (response_.Content != null && response_.Content.Headers != null)
                        {
                            foreach (var item_ in response_.Content.Headers)
                                headers_[item_.Key] = item_.Value;
                        }

                        ProcessResponse(client_, response_);

                        var status_ = (int)response_.StatusCode;
                        if (status_ == 301)
                        {
                            string responseText_ = (response_.Content == null) ? string.Empty : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("Moved Permanently", status_, responseText_, headers_, null);
                        }
                        else

                        if (status_ == 200 || status_ == 204)
                        {
                            using (System.IO.Stream dataStream = response_.Content.ReadAsStreamAsync().GetAwaiter().GetResult())
                            {
                                using (System.IO.StreamReader reader = new System.IO.StreamReader(dataStream))
                                {
                                    string responseFromServer = reader.ReadToEnd();
                                    return responseFromServer;
                                    //return JsonConvert.DeserializeObject<dynamic>(responseFromServer);
                                }
                            }

                            //string responseText_ = (response_.Content == null) ? string.Empty : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                        }
                        else
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("The HTTP status code of the response was not expected (" + status_ + ").", status_, responseData_, headers_, null);
                        }
                    }
                    catch
                    {
                        throw;
                    }
                    finally
                    {
                        if (disposeResponse_)
                            response_.Dispose();
                    }
                }
            }
            finally
            {
                if (disposeClient_)
                    client_.Dispose();
            }
        }

        public virtual async System.Threading.Tasks.Task<List<FileFormatEndpoint>> GetFileFormats(System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            var urlBuilder_ = new System.Text.StringBuilder();
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "").Append("/file-formats");

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    request_.Method = new System.Net.Http.HttpMethod("GET");
                    request_.Headers.Accept.Add(System.Net.Http.Headers.MediaTypeWithQualityHeaderValue.Parse("application/json"));

                    PrepareRequest(client_, request_, urlBuilder_);

                    var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url_, System.UriKind.RelativeOrAbsolute);

                    PrepareRequest(client_, request_, url_);

                    var response_ = await _retryPolicy.ExecuteAsync(() => client_.SendAsync(CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);
                    var disposeResponse_ = true;
                    try
                    {
                        var headers_ = System.Linq.Enumerable.ToDictionary(response_.Headers, h_ => h_.Key, h_ => h_.Value);
                        if (response_.Content != null && response_.Content.Headers != null)
                        {
                            foreach (var item_ in response_.Content.Headers)
                                headers_[item_.Key] = item_.Value;
                        }

                        ProcessResponse(client_, response_);

                        var status_ = (int)response_.StatusCode;
                        if (status_ == 200)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<List<FileFormatEndpoint>>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            return objectResponse_.Object;
                        }
                        else
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("The HTTP status code of the response was not expected (" + status_ + ").", status_, responseData_, headers_, null);
                        }
                    }
                    finally
                    {
                        if (disposeResponse_)
                            response_.Dispose();
                    }
                }
            }
            finally
            {
                if (disposeClient_)
                    client_.Dispose();
            }
        }


        public string GetReportRequest(Guid scanId, string fileFormat,
            double poolInterval = 0.5)
        {
            return GetReportRequest(new()
            {
                ScanId = scanId,
                FileFormat = fileFormat
            }, poolInterval);
        }

        public string GetReportRequest(ScanData scanData,
            double poolInterval = 0.5)
        {
            if (scanData == null)
                throw new ArgumentNullException(nameof(scanData));

            if (scanData.ScanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanData.ScanId));

            if (string.IsNullOrWhiteSpace(scanData.FileFormat))
                throw new ArgumentNullException(nameof(scanData.FileFormat));

            if (poolInterval < 0)
                throw new ArgumentOutOfRangeException(nameof(poolInterval));

            var listOfSupportedFormats = GetFileFormats().Result
                .Single(y => y.Route == "/requests")
                .FileFormats;

            if (!listOfSupportedFormats.Contains(scanData.FileFormat, StringComparer.OrdinalIgnoreCase))
            {
                throw new NotSupportedException($"Format \"{scanData.FileFormat}\" NOT Supported. Supported Formats: {string.Join(";", listOfSupportedFormats)}");
            }

            ExportDataResponse createReportOutut = CreateReportAsync(scanData).Result;

            if (createReportOutut.ExportId == Guid.Empty)
                throw new Exception($"Error getting report of scan {scanData.ScanId}");

            ExportStatusDetails statusResponse;
            do
            {
                statusResponse = GetReportStatusAsync(createReportOutut.ExportId).Result;

                if (statusResponse.IsFailed())
                {
                    throw new Exception($"Failed to generate a report for scan {scanData.ScanId}.");
                }

                if (!statusResponse.IsCompleted())
                    Thread.Sleep(TimeSpan.FromSeconds(poolInterval));
            }
            while (!statusResponse.IsCompleted());

            return DownloadScanReport(statusResponse.FileUrl).Result;
        }

        public ScanReportJson GetScanReport(Guid scanId, double poolInterval = 0.5)
        {
            return JsonConvert.DeserializeObject<ScanReportJson>(
                GetReportRequest(scanId, "ScanReportJson", poolInterval: poolInterval));
        }

        protected struct ObjectResponseResult<T>
        {
            public ObjectResponseResult(T responseObject, string responseText)
            {
                this.Object = responseObject;
                this.Text = responseText;
            }

            public T Object { get; }

            public string Text { get; }
        }

        public bool ReadResponseAsString { get; set; }

        protected virtual async System.Threading.Tasks.Task<ObjectResponseResult<T>> ReadObjectResponseAsync<T>(System.Net.Http.HttpResponseMessage response, System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IEnumerable<string>> headers, System.Threading.CancellationToken cancellationToken)
        {
            if (response == null || response.Content == null)
            {
                return new ObjectResponseResult<T>(default(T), string.Empty);
            }

            if (ReadResponseAsString)
            {
                var responseText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                try
                {
                    var typedBody = Newtonsoft.Json.JsonConvert.DeserializeObject<T>(responseText, JsonSerializerSettings);
                    return new ObjectResponseResult<T>(typedBody, responseText);
                }
                catch (Newtonsoft.Json.JsonException exception)
                {
                    var message = "Could not deserialize the response body string as " + typeof(T).FullName + ".";
                    throw new ApiException(message, (int)response.StatusCode, responseText, headers, exception);
                }
            }
            else
            {
                try
                {
                    using (var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                    using (var streamReader = new System.IO.StreamReader(responseStream))
                    using (var jsonTextReader = new Newtonsoft.Json.JsonTextReader(streamReader))
                    {
                        var serializer = Newtonsoft.Json.JsonSerializer.Create(JsonSerializerSettings);
                        var typedBody = serializer.Deserialize<T>(jsonTextReader);
                        return new ObjectResponseResult<T>(typedBody, string.Empty);
                    }
                }
                catch (Newtonsoft.Json.JsonException exception)
                {
                    var message = "Could not deserialize the response body stream as " + typeof(T).FullName + ".";
                    throw new ApiException(message, (int)response.StatusCode, string.Empty, headers, exception);
                }
            }
        }

        private string ConvertToString(object value, System.Globalization.CultureInfo cultureInfo)
        {
            if (value == null)
            {
                return "";
            }

            if (value is System.Enum)
            {
                var name = System.Enum.GetName(value.GetType(), value);
                if (name != null)
                {
                    var field = System.Reflection.IntrospectionExtensions.GetTypeInfo(value.GetType()).GetDeclaredField(name);
                    if (field != null)
                    {
                        var attribute = System.Reflection.CustomAttributeExtensions.GetCustomAttribute(field, typeof(System.Runtime.Serialization.EnumMemberAttribute))
                            as System.Runtime.Serialization.EnumMemberAttribute;
                        if (attribute != null)
                        {
                            return attribute.Value != null ? attribute.Value : name;
                        }
                    }

                    var converted = System.Convert.ToString(System.Convert.ChangeType(value, System.Enum.GetUnderlyingType(value.GetType()), cultureInfo));
                    return converted == null ? string.Empty : converted;
                }
            }
            else if (value is bool)
            {
                return System.Convert.ToString((bool)value, cultureInfo).ToLowerInvariant();
            }
            else if (value is byte[])
            {
                return System.Convert.ToBase64String((byte[])value);
            }
            else if (value.GetType().IsArray)
            {
                var array = System.Linq.Enumerable.OfType<object>((System.Array)value);
                return string.Join(",", System.Linq.Enumerable.Select(array, o => ConvertToString(o, cultureInfo)));
            }

            var result = System.Convert.ToString(value, cultureInfo);
            return result == null ? "" : result;
        }
    }
}
