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
        public string ErrorMessage { get; set; }

        public ScanResultDetails SASTResults { get; set; }
        public ScanResultDetails ScaResults { get; set; }
        public ScanResultDetails KicsResults { get; set; }
    }

    public class ScanResultDetails
    {
        public uint Total { get; set; }
        public uint High { get; set; }
        public uint Medium { get; set; }
        public uint Low { get; set; }
        public uint Info { get; set; }
        public int Queries { get; set; }
        public ICollection<string> LanguagesDetected { get; set; }
    }
}
