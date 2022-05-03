using Newtonsoft.Json;
namespace Checkmarx.API.AST.Models
{
    public partial class EngineServer
    {
        [JsonProperty("id")]
        public long Id { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("link")]
        public object Link { get; set; }
    }
}
