using System;
using System.Collections.Generic;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Checkmarx.API.AST.Models
{
    public partial class Scan
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("status")]
        public StatusEnum Status { get; set; }

        [JsonProperty("statusDetails")]
        public ICollection<StatusDetails> StatusDetails { get; set; }

        [JsonProperty("positionInQueue")]
        public int PositionInQueue { get; set; }

        [JsonProperty("projectId")]
        public string ProjectId { get; set; }

        [JsonProperty("branch")]
        public string Branch { get; set; }

        [JsonProperty("commitId")]
        public string CommitId { get; set; }

        [JsonProperty("commitTag")]
        public string CommitTag { get; set; }

        [JsonProperty("uploadUrl")]
        public string UploadUrl { get; set; }

        [JsonProperty("createdAt")]
        public DateTimeOffset CreatedAt { get; set; }

        [JsonProperty("updatedAt")]
        public DateTimeOffset UpdatedAt { get; set; }

        [JsonProperty("userAgent")]
        public string UserAgent { get; set; }

        [JsonProperty("initiator")]
        public string Initiator { get; set; }

        [JsonProperty("tags")]
        public IDictionary<string, string> Tags { get; set; }

        [JsonProperty("metadata")]
        public Metadata Metadata { get; set; }

        private IDictionary<string, object> _additionalProperties = new System.Collections.Generic.Dictionary<string, object>();
        [JsonProperty("additionalProperties")]
        public IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties; }
            set { _additionalProperties = value; }
        }

        public IEnumerable<SASTScanResults> SASTResults { get; set; }

        public static Scan FromJson(string json) => JsonConvert.DeserializeObject<Scan>(json, Converter.Settings);
    }

    public enum StatusEnum
    {

        [System.Runtime.Serialization.EnumMember(Value = @"Queued")]
        Queued = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"Running")]
        Running = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"Completed")]
        Completed = 2,

        [System.Runtime.Serialization.EnumMember(Value = @"Failed")]
        Failed = 3,

        [System.Runtime.Serialization.EnumMember(Value = @"Partial")]
        Partial = 4,

        [System.Runtime.Serialization.EnumMember(Value = @"Canceled")]
        Canceled = 5,

    }

    public class Metadata
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("Handler")]
        public Handler Handler { get; set; }

        [JsonProperty("configs")]
        public List<MetadataConfig> Configs { get; set; }

        [JsonProperty("project")]
        public object Project { get; set; }
    }

    public class MetadataConfig
    {
        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("value")]
        public MetadataValue Value { get; set; }
    }

    public class MetadataValue
    {
        [JsonProperty("incremental")]
        public bool Incremental { get; set; }
    }

    public class Handler
    {
        [JsonProperty("UploadHandler")]
        public UploadHandler UploadHandler { get; set; }
    }

    public class UploadHandler
    {
        [JsonProperty("branch")]
        public string Branch { get; set; }

        [JsonProperty("upload_url")]
        public string UploadUrl { get; set; }
    }

    public partial class StatusDetails
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("status")]
        public string Status { get; set; }

        [JsonProperty("details")]
        public string Details { get; set; }
    }

    public static class Serialize
    {
        public static string ToJson(this Scan self) => JsonConvert.SerializeObject(self, Converter.Settings);
    }

    internal static class Converter
    {
        public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
        {
            MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
            DateParseHandling = DateParseHandling.None,
            Converters =
            {
                new IsoDateTimeConverter { DateTimeStyles = DateTimeStyles.AssumeUniversal }
            },
        };
    }
}
