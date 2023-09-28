using System;
using System.Collections.Generic;
using System.Text;

namespace Checkmarx.API.AST.Models
{
    public class ScanDetails
    {
        public Guid Id { get; set; }

        public string Status { get; set; }
        public bool Successful { get; set; }
        public string Preset { get; set; }
        public long LoC { get; set; }
        public string Branch { get; set; }
        public string InitiatorName { get; set; }
        public string SourceType { get; set; }
        public string SourceOrigin { get; set; }
        public string Type { get; set; }
        public string RepoUrl { get; set; }
        public string UploadUrl { get; set; }
        public DateTimeOffset? FinishedOn { get; set; }
        public TimeSpan Duration { get; set; }
        public string Languages { get; set; }
        public string ErrorMessage { get; set; }

        public ScanResultDetails SASTResults { get; set; }
        public ScanResultDetails ScaResults { get; set; }
        public ScanResultDetails KicsResults { get; set; }
    }

    public class ScanResultDetails
    {
        public Guid Id { get; set; }
        public bool Successful { get; set; }
        public string Status { get; set; }
        public string Details { get; set; }
        public int? Total { get; set; }
        public int? High { get; set; }
        public int? Medium { get; set; }
        public int? Low { get; set; }
        public int? Info { get; set; }
        public int? ToVerify { get; set; }
        public int? NotExploitableMarked { get; set; }
        public int? PNEMarked { get; set; }
        public int? OtherStates { get; set; }

        public int? HighToVerify { get; set; }
        public int? MediumToVerify { get; set; }
        public int? LowToVerify { get; set; }

        public int? Queries { get; set; }
        public ICollection<string> LanguagesDetected { get; set; }

        public int? QueriesHigh { get; set; }
        public int? QueriesMedium { get; set; }
        public int? QueriesLow { get; set; }
    }
}
