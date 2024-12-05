using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Services
{
    public class GraphQLClient
    {
        private readonly HttpClient _httpClient;
        private readonly string _endpointUri;

        public GraphQLClient(string endpointUri, HttpClient httpClient)
        {
            if (string.IsNullOrWhiteSpace(endpointUri))
                throw new ArgumentException("Endpoint URI cannot be null or empty", nameof(endpointUri));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _endpointUri = endpointUri;
        }

        public async Task<string> ExecuteQueryAsync(string query, object variables = null)
        {
            if (string.IsNullOrWhiteSpace(query))
                throw new ArgumentException("Query cannot be null or empty", nameof(query));

            var requestBody = new
            {
                query,
                variables
            };

            var jsonContent = new StringContent(
                JsonSerializer.Serialize(requestBody),
                Encoding.UTF8,
                "application/json"
            );

            var response = await _httpClient.PostAsync(_endpointUri, jsonContent);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException($"Request failed with status code {response.StatusCode}: {errorContent}");
            }

            return await response.Content.ReadAsStringAsync();
        }

        public SCALegalRisks GetSCAScanLegalRisks(string query, object variables = null)
        {
            var response = ExecuteQueryAsync(query, variables).GetAwaiter().GetResult();
            return JsonSerializer.Deserialize<SCALegalRisks>(
                response,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }
    }

    #region LegalRisk

    public class SCALegalRisks
    {
        public SCALegalRisksData Data { get; set; }
    }

    public class SCALegalRisksData
    {
        public LegalRisksByScanId LegalRisksByScanId { get; set; }
    }

    public class LegalRisksByScanId
    {
        public int TotalCount { get; set; }
        public RisksLevelCounts RisksLevelCounts { get; set; }
    }

    public class RisksLevelCounts
    {
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int None { get; set; }
        public int Empty { get; set; }
    }

    #endregion
}
