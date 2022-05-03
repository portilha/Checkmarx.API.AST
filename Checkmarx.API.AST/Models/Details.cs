using Newtonsoft.Json;
namespace Checkmarx.API.AST.Models
{
    public partial class Details
    {
        [JsonProperty("stage")]
        public string Stage { get; set; }

        [JsonProperty("step")]
        public string Step { get; set; }
    }
}
