using System;
using System.Collections.Generic;

namespace Checkmarx.API.AST.Models
{

    public class ScanResultDetails
    {
        private readonly static string CompletedStage = Checkmarx.API.AST.Services.Scans.Status.Completed.ToString();

        public Guid Id { get; set; }

        /// <summary>
        /// Is successful or completed.
        /// </summary>
        public bool Successful { get { return Status == CompletedStage; } }

        public string Status { get; set; }

        public int? Total { get; set; }

        public int? Critical { get; set; }
        public int? High { get; set; }
        public int? Medium { get; set; }
        public int? Low { get; set; }
        public int? Info { get; set; }

        public int? ToVerify { get; set; }
    }

    public class SASTScanResultDetails : ScanResultDetails
    {
        public int? Queries { get; set; }
        public ICollection<string> LanguagesDetected { get; set; }

        public int? QueriesCritical { get; set; }
        public int? QueriesHigh { get; set; }
        public int? QueriesMedium { get; set; }
        public int? QueriesLow { get; set; }

        public int? NotExploitableMarked { get; set; }
        public int? PNEMarked { get; set; }
        public int? OtherStates { get; set; }

        public int? CriticalToVerify { get; set; }
        public int? HighToVerify { get; set; }
        public int? MediumToVerify { get; set; }
        public int? LowToVerify { get; set; }
    }

}
