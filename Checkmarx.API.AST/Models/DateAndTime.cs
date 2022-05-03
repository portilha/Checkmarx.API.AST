using System;
using Newtonsoft.Json;
namespace Checkmarx.API.AST.Models
{
    public partial class DateAndTime
    {
        [JsonProperty("startedOn")]
        public DateTimeOffset? StartedOn { get; set; }

        [JsonProperty("finishedOn")]
        public DateTimeOffset? FinishedOn { get; set; }

        [JsonProperty("engineStartedOn")]
        public DateTimeOffset? EngineStartedOn { get; set; }

        [JsonProperty("engineFinishedOn")]
        public DateTimeOffset? EngineFinishedOn { get; set; }
    }
}
