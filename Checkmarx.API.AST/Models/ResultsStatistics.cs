using Newtonsoft.Json;
namespace Checkmarx.API.AST.Models
{
    public partial class ResultsStatistics
    {
        [JsonProperty("link")]
        public object Link { get; set; }
    }
}
