namespace Checkmarx.API.AST.Models
{
    using Newtonsoft.Json;

    public partial class Link
    {
        [JsonProperty("rel")]
        public string Rel { get; set; }

        [JsonProperty("uri")]
        public string Uri { get; set; }
    }
}

