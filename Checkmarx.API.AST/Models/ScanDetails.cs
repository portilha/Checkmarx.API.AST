using System;
using System.Collections.Generic;
using System.Text;

namespace Checkmarx.API.AST.Models
{
    public class ScanDetails
    {
        public Guid Id { get; set; }
        public string Preset { get; set; }
        public long LoC { get; set; }
        public DateTimeOffset? FinishedOn { get; set; }
        public TimeSpan Duration { get; set; }
        public string Languages { get; set; }

        public uint ResultsHigh { get; set; }
        public uint ResultsMedium { get; set; }
        public uint ResultsLow { get; set; }
        public uint ResultsInfo { get; set; }
        public int ResultsQueries { get; set; }
        public ICollection<string> ResultsLanguagesDetected { get; set; }
    }
}
