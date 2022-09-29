using System;
using System.Collections.Generic;

namespace Checkmarx.API.AST.Models
{
    public class SASTScanResults
    {
        public Guid Id { get; set; }

        public int LoC { get; set; }

        public int FailedLoC { get; set; }

        /// <summary>
        /// Get from the comments on the Queries
        /// </summary>
        public ICollection<string> TunningInfo { get; set; }

        // True Positives
        public uint High { get; set; }

        public uint Medium { get; set; }

        public uint Low { get; set; }

        public uint Info { get; set; }

        public uint ToVerify { get; set; }

        public int FalseNegatives { get; set; }

        public int FalsePositives { get; set; }

        public int Queries { get; set; }

        public ICollection<string> LanguagesDetected { get; set; }
    }

    public class SCAScanResults
    {
        public Guid Id { get; set; }

        public uint High { get; set; }

        public uint Medium { get; set; }

        public uint Low { get; set; }

        public uint Info { get; set; }
    }

    public class KicksScanResults
    {
        public Guid Id { get; set; }

        public uint High { get; set; }

        public uint Medium { get; set; }

        public uint Low { get; set; }

        public uint Info { get; set; }
    }
}
