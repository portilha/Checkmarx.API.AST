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

        public int? FalseNegatives { get; set; }

        public int? FalsePositives { get; set; }

        public int? Queries { get; set; }

        public ICollection<string> LanguagesDetected { get; set; }
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
