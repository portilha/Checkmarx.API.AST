using Newtonsoft.Json;
namespace Checkmarx.API.AST.Models
{
    public partial class FinishedScanStatus
    {
        [JsonProperty("id")]
        public long Id { get; set; }

        [JsonProperty("value")]
        public string Value { get; set; }
    }
}
