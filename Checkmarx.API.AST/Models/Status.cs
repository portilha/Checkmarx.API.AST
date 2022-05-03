using Newtonsoft.Json;
namespace Checkmarx.API.AST.Models
{
    public partial class Status
    {
        [JsonProperty("id")]
        public long Id { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("details")]
        public Details Details { get; set; }
    }
}

