using System;
using System.Collections.Generic;

namespace Checkmarx.API.AST.Models
{
    public class ScanResults
    {
        public Guid Id { get; set; }

        public bool Successful { get; set; }
        public string Status { get; set; }
        public string Details { get; set; }

        public long LoC { get; set; }

        public int FailedLoC { get; set; }

        /// <summary>
        /// Get from the comments on the Queries
        /// </summary>
        public ICollection<string> TunningInfo { get; set; }

        // True Positives
        public int? High { get; set; }

        public int? Medium { get; set; }

        public int? Low { get; set; }

        public int? Info { get; set; }

        public int? ToVerify { get; set; }

        public int? HighToVerify { get; set; }

        public int? MediumToVerify { get; set; }

        public int? LowToVerify { get; set; }

        public int? NotExploitableMarked { get; set; }

        public int? PNEMarked { get; set; }

        public int? OtherStates { get; set; }

        public int? Queries { get; set; }

        public int? QueriesHigh { get; set; }
        public int? QueriesMedium { get; set; }
        public int? QueriesLow { get; set; }

        public int? FPRemoved { get; set; }
        public int? FNAdded { get; set; }
        public int? FNAddedHigh { get; set; }
        public int? FNAddedMedium { get; set; }
        public int? FNAddedLow { get; set; }

        public ICollection<string> LanguagesDetected { get; set; }

        public bool IsCompleted()
        {
            return Status.ToLower() == "completed";
        }
    }

    //public class SCAScanResults
    //{
    //    public Guid Id { get; set; }

    //    public int High { get; set; }

    //    public int Medium { get; set; }

    //    public int Low { get; set; }

    //    public int Info { get; set; }
    //}

    //public class KicsScanResults
    //{
    //    public Guid Id { get; set; }

    //    public int? High { get; set; }

    //    public int? Medium { get; set; }

    //    public int? Low { get; set; }

    //    public int? Info { get; set; }
    //}
}
