using Checkmarx.API.AST.Services.KicsResults;
using Checkmarx.API.AST.Services.ResultsOverview;
using Checkmarx.API.AST.Services.ResultsSummary;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.Scans;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Checkmarx.API.AST.Models
{
    public class ScanDetails
    {
        private ASTClient _client;
        private Services.Scans.Scan _scan;

        private readonly static string CompletedStage = Checkmarx.API.AST.Services.Scans.Status.Completed.ToString();

        public ScanDetails(ASTClient client, Services.Scans.Scan scan)
        {
            if (client == null)
                throw new ArgumentNullException(nameof(client));

            if (scan == null)
                throw new ArgumentNullException(nameof(scan));

            _client = client;
            _scan = scan;
        }

        public Guid Id => _scan.Id;

        public Status Status => _scan.Status;
        public bool Successful => Status ==  Status.Completed || Status == Status.Partial;
        public string InitiatorName => _scan.Initiator;
        public string Branch => _scan.Branch;
        public string SourceType => _scan.SourceType;
        public string SourceOrigin => _scan.SourceOrigin;
        public DateTimeOffset? FinishedOn => _scan.UpdatedAt.DateTime;
        public TimeSpan Duration => _scan.UpdatedAt.DateTime - _scan.CreatedAt.DateTime;
        public string Type => _scan.Metadata?.Type;
        public string RepoUrl => _scan.Metadata?.Handler?.GitHandler?.RepoUrl;
        public string UploadUrl => _scan.Metadata?.Handler?.UploadHandler?.UploadUrl;

        private string preset;
        public string Preset
        {
            get
            {
                if (loC == null)
                    loadPresetAndLoc();

                return preset;
            }
            private set { preset=value; }
        }

        private long? loC = null;
        public long LoC
        {
            get
            {
                if (loC == null)
                {
                    loadPresetAndLoc();
                }
                return loC.Value;
            }
            private set => loC=value;
        }

        public string Languages
        {
            get
            {
                if (SASTResults != null && SASTResults.LanguagesDetected != null)
                {
                    return string.Join(";", SASTResults.LanguagesDetected.Where(x => x != "Common").Select(x => x).ToList());
                }

                return null;
            }
        }

        private void loadPresetAndLoc()
        {
            // Get sast metadata
            try
            {
                // TODO: Refactor this to avoid throwing exceptions all the time regarding a known situation.
                ScanInfo metadata = _client.SASTMetadata.GetMetadataAsync(Id).Result;
                if (metadata != null)
                {
                    Preset = metadata.QueryPreset;
                    LoC = metadata.Loc;
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"Error fetching project {_scan.ProjectId} Preset and LoC. Reason {ex.Message.Replace("\n", " ")}");
            }

            if (string.IsNullOrWhiteSpace(preset))
            {
                Preset = _client.GetScanPresetFromConfigurations(_scan.ProjectId, Id);
            }

            LoC = -1;
        }

        private ResultsSummary _resultsSummary = null;
        private ResultsSummary ResultsSummary
        {
            get
            {
                if (_resultsSummary == null)
                    _resultsSummary = _client.GetResultsSummaryById(Id).FirstOrDefault();

                return _resultsSummary;
            }
        }

        public ScanResultDetails _sastResults;

        public ScanResultDetails SASTResults
        {
            get
            {
                if (_sastResults != null)
                    return _sastResults;

                if (!Successful)
                    return null;

                var sastStatusDetails = _scan.StatusDetails.SingleOrDefault(x => x.Name == ASTClient.SAST_Engine);
                if (sastStatusDetails == null)
                {
                    return null;
                }

                _sastResults = new ScanResultDetails
                {
                    Id = Id,
                    Status = sastStatusDetails.Status,
                    Successful = sastStatusDetails.Status == CompletedStage
                };

                if (_sastResults.Successful)
                {
                    try
                    {
                        UpdateSASTScanResultDetailsBasedOnResultsSummary(_sastResults, ResultsSummary);
                    }
                    catch (Exception)
                    {
                        updateSASTScanResultDetailsBasedOnScanVulnerabilities(_sastResults, Id);
                    }
                }

                return _sastResults;
            }
        }

        /// <summary>
        /// Very performance intensive.
        /// </summary>
        /// <param name="scanDetails"></param>
        /// <param name="scanId"></param>
        /// <returns></returns>
        private void updateSASTScanResultDetailsBasedOnScanVulnerabilities(ScanResultDetails model, Guid scanId)
        {
            var sastResults = SASTVulnerabilities;
            if (sastResults == null)
                return;

            var results = SASTVulnerabilities.Where(x => x.State != ResultsState.NOT_EXPLOITABLE);

            model.Id = scanId;
            model.Total = results.Count();
            model.High = results.Where(x => x.Severity == ResultsSeverity.HIGH).Count();
            model.Medium = results.Where(x => x.Severity == ResultsSeverity.MEDIUM).Count();
            model.Low = results.Where(x => x.Severity == ResultsSeverity.LOW).Count();
            model.Info = results.Where(x => x.Severity == ResultsSeverity.INFO).Count();

            model.HighToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.HIGH && x.State == ResultsState.TO_VERIFY).Count();
            model.MediumToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.MEDIUM && x.State == ResultsState.TO_VERIFY).Count();
            model.LowToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.LOW && x.State == ResultsState.TO_VERIFY).Count();

            model.ToVerify = sastResults.Where(x => x.State == ResultsState.TO_VERIFY).Count();
            model.NotExploitableMarked = sastResults.Where(x => x.State == ResultsState.NOT_EXPLOITABLE).Count();
            model.PNEMarked = sastResults.Where(x => x.State == ResultsState.PROPOSED_NOT_EXPLOITABLE).Count();
            model.OtherStates = sastResults.Where(x =>
                                                        x.State != ResultsState.CONFIRMED &&
                                                        x.State != ResultsState.URGENT &&
                                                        x.State != ResultsState.NOT_EXPLOITABLE &&
                                                        x.State != ResultsState.PROPOSED_NOT_EXPLOITABLE &&
                                                        x.State != ResultsState.TO_VERIFY).Count();
            model.LanguagesDetected = sastResults.Select(x => x.LanguageName).Distinct().ToList();
            //model.Queries = report.ScanResults.Sast.Languages.Sum(x => x.Queries.Count());

            try
            {
                // Scan query categories
                var scanResultsHigh = results.Where(x => x.Severity == ResultsSeverity.HIGH);
                var scanResultsMedium = results.Where(x => x.Severity == ResultsSeverity.MEDIUM);
                var scanResultsLow = results.Where(x => x.Severity == ResultsSeverity.LOW);

                var scanQueriesHigh = scanResultsHigh.Select(x => x.QueryID).Distinct().ToList();
                var scanQueriesMedium = scanResultsMedium.Select(x => x.QueryID).Distinct().ToList();
                var scanQueriesLow = scanResultsLow.Select(x => x.QueryID).Distinct().ToList();

                model.QueriesHigh = scanQueriesHigh.Count();
                model.QueriesMedium = scanQueriesMedium.Count();
                model.QueriesLow = scanQueriesLow.Count();
                model.Queries = model.QueriesHigh + model.QueriesMedium + model.QueriesLow;
            }
            catch
            {
                model.QueriesHigh = null;
                model.QueriesMedium = null;
                model.QueriesLow = null;
            }
        }

        /// <summary>
        /// Very performance intensive.
        /// </summary>
        /// <param name="scanDetails"></param>
        /// <param name="resultsSummary"></param>
        /// <returns></returns>
        private void UpdateSASTScanResultDetailsBasedOnResultsSummary(ScanResultDetails model, ResultsSummary resultsSummary)
        {
            if (resultsSummary == null)
                return;

            var sastCounters = resultsSummary.SastCounters;

            model.Id = new Guid(resultsSummary.ScanId);
            model.High = sastCounters.SeverityCounters
                .Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.HIGH).Sum(x => x.Counter);
            model.Medium = sastCounters.SeverityCounters
                .Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.MEDIUM).Sum(x => x.Counter);
            model.Low = sastCounters.SeverityCounters
                .Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.LOW).Sum(x => x.Counter);
            model.Info = sastCounters.SeverityCounters
                .Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.INFO).Sum(x => x.Counter);

            // ToVerify -> we dont want to include the info vulns
            model.ToVerify = sastCounters.StateCounters.Where(x => x.State == ResultsSummaryState.TO_VERIFY).Sum(x => x.Counter) - model.Info;

            model.Total = sastCounters.TotalCounter;

            model.LanguagesDetected = sastCounters.LanguageCounters.Select(x => x.Language).Distinct().ToList();
            model.Queries = sastCounters.QueriesCounters.Count;

            // Number of queries
            try
            {
                // Scan query categories
                var scanResults = SASTVulnerabilities;

                var scanResultsHigh = scanResults.Where(x => x.Severity == ResultsSeverity.HIGH);
                var scanResultsMedium = scanResults.Where(x => x.Severity == ResultsSeverity.MEDIUM);
                var scanResultsLow = scanResults.Where(x => x.Severity == ResultsSeverity.LOW);

                var scanQueriesHigh = scanResultsHigh.Select(x => x.QueryID).Distinct().ToList();
                var scanQueriesMedium = scanResultsMedium.Select(x => x.QueryID).Distinct().ToList();
                var scanQueriesLow = scanResultsLow.Select(x => x.QueryID).Distinct().ToList();

                model.QueriesHigh = scanQueriesHigh.Count();
                model.QueriesMedium = scanQueriesMedium.Count();
                model.QueriesLow = scanQueriesLow.Count();
                model.Queries = model.QueriesHigh + model.QueriesMedium + model.QueriesLow;

                model.HighToVerify = scanResults.Where(x => x.Severity == ResultsSeverity.HIGH && x.State == ResultsState.TO_VERIFY).Count();
                model.MediumToVerify = scanResults.Where(x => x.Severity == ResultsSeverity.MEDIUM && x.State == ResultsState.TO_VERIFY).Count();
                model.LowToVerify = scanResults.Where(x => x.Severity == ResultsSeverity.LOW && x.State == ResultsState.TO_VERIFY).Count();

                model.ToVerify = scanResults.Where(x => x.State == ResultsState.TO_VERIFY).Count();
                model.NotExploitableMarked = scanResults.Where(x => x.State == ResultsState.NOT_EXPLOITABLE).Count();
                model.PNEMarked = scanResults.Where(x => x.State == ResultsState.PROPOSED_NOT_EXPLOITABLE).Count();
                model.OtherStates = scanResults.Where(x => x.State != ResultsState.CONFIRMED && x.State != ResultsState.URGENT && x.State != ResultsState.NOT_EXPLOITABLE && x.State != ResultsState.PROPOSED_NOT_EXPLOITABLE && x.State != ResultsState.TO_VERIFY).Count();
            }
            catch
            {
                model.QueriesHigh = null;
                model.QueriesMedium = null;
                model.QueriesLow = null;
            }
        }


        public ScanResultDetails _scaResults = null;
        public ScanResultDetails ScaResults
        {
            get
            {
                if (_scaResults != null)
                    return _scaResults;

                if (!Successful)
                    return null;

                var scaStatusDetails = _scan.StatusDetails.SingleOrDefault(x => x.Name == ASTClient.SCA_Engine);
                if (scaStatusDetails == null)
                {
                    return null;
                }

                _scaResults = new ScanResultDetails
                {
                    Id = Id,
                    Status = scaStatusDetails.Status,
                    Successful = scaStatusDetails.Status == CompletedStage
                };

                if (_scaResults.Successful)
                {
                    try
                    {
                        updateScaScanResultDetailsBasedOnResultsSummary(_scaResults, ResultsSummary);
                    }
                    catch (Exception)
                    {
                        updateSCAScanResultDetailsBasedOnSCAVulnerabilities(_scaResults, _scan.ProjectId, Id);
                    }
                }

                return _scaResults;
            }
        }

        private void updateSCAScanResultDetailsBasedOnSCAVulnerabilities(ScanResultDetails model, Guid projId, Guid scanId)
        {
            // When it is a scan with only SCA engine and 0 results, for some reason other APIs returns null in the sca scan status and results
            // This is the only one i found that returns something
            var resultsOverview = _client.ResultsOverview.ProjectsAsync(new List<Guid>() { projId }).Result;
            if (resultsOverview != null)
            {
                var resultOverview = resultsOverview.FirstOrDefault();
                if (resultOverview != null && resultOverview.scaCounters != null)
                {
                    if (resultOverview.scaCounters.severityCounters != null && resultOverview.scaCounters.severityCounters.Any())
                    {
                        model.High = resultOverview.scaCounters.severityCounters.Where(x => x.Severity.ToUpper() == "HIGH").Sum(x => x.Counter);
                        model.Medium = resultOverview.scaCounters.severityCounters.Where(x => x.Severity.ToUpper() == "MEDIUM").Sum(x => x.Counter);
                        model.Low = resultOverview.scaCounters.severityCounters.Where(x => x.Severity.ToUpper() == "LOW").Sum(x => x.Counter);
                        model.Info = resultOverview.scaCounters.severityCounters.Where(x => x.Severity.ToUpper() == "INFO").Sum(x => x.Counter);
                    }
                    else
                    {
                        model.High = 0;
                        model.Medium = 0;
                        model.Low = 0;
                        model.Info = 0;
                    }

                    if (resultOverview.scaCounters.state != null && resultOverview.scaCounters.state.Any())
                        model.ToVerify = resultOverview.scaCounters.state.Where(x => x.state.ToUpper() == "TO_VERIFY").Sum(x => x.counter);
                    else
                        model.ToVerify = 0;

                    model.Total = resultOverview.scaCounters.totalCounter;
                }
            }
        }

        private void updateScaScanResultDetailsBasedOnResultsSummary(ScanResultDetails model, ResultsSummary resultsSummary)
        {
            if (resultsSummary == null)
            {
                return;
            }

            var scaCounters = resultsSummary.ScaCounters;

            model.Id = new Guid(resultsSummary.ScanId);
            model.High = scaCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.HIGH).Sum(x => x.Counter);
            model.Medium = scaCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.MEDIUM).Sum(x => x.Counter);
            model.Low = scaCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.LOW).Sum(x => x.Counter);
            model.Info = scaCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.INFO).Sum(x => x.Counter);
            model.ToVerify = scaCounters.StateCounters.Where(x => x.State == ResultsSummaryState.TO_VERIFY).Sum(x => x.Counter);
            model.Total = scaCounters.TotalCounter;
        }


        public ScanResultDetails _kicsResults = null;
        public ScanResultDetails KicsResults
        {
            get
            {
                if (_kicsResults != null)
                    return _kicsResults;

                if (!Successful)
                    return null;

                var kicsStatusDetails = _scan.StatusDetails.SingleOrDefault(x => x.Name == ASTClient.KICS_Engine);
                if (kicsStatusDetails == null)
                {
                    return null;
                }

                _kicsResults = new ScanResultDetails
                {
                    Id = Id,
                    Status = kicsStatusDetails.Status,
                    Successful = kicsStatusDetails.Status == CompletedStage
                };

                if (_kicsResults.Successful)
                {
                    try
                    {
                        updateKicsScanResultDetailsBasedOnResultsSummary(_kicsResults, ResultsSummary);
                    }
                    catch (Exception)
                    {
                        updateKicsScanResultDetailsBasedOnKicsVulnerabilities(_kicsResults, Id);
                    }
                }

                return _kicsResults;
            }
        }

        private void updateKicsScanResultDetailsBasedOnKicsVulnerabilities(ScanResultDetails model, Guid scanId)
        {
            var kicsResults = _client.GetKicsScanResultsById(scanId);
            if (kicsResults == null)
            {
                return;
            }

            var results = kicsResults.Where(x => x.State != KicsStateEnum.NOT_EXPLOITABLE);

            model.Id = scanId;
            model.Total = results.Count();
            model.High = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.HIGH).Count();
            model.Medium = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.MEDIUM).Count();
            model.Low = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.LOW).Count();
            model.Info = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.INFO).Count();
            model.ToVerify = kicsResults.Where(x => x.State == KicsStateEnum.TO_VERIFY).Count();
        }

        private void updateKicsScanResultDetailsBasedOnResultsSummary(ScanResultDetails model, ResultsSummary resultsSummary)
        {
            if (resultsSummary == null)
            {
                return;
            }

            var kicsCounters = resultsSummary.KicsCounters;

            model.Id = new Guid(resultsSummary.ScanId);
            model.High = kicsCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.HIGH).Sum(x => x.Counter);
            model.Medium = kicsCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.MEDIUM).Sum(x => x.Counter);
            model.Low = kicsCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.LOW).Sum(x => x.Counter);
            model.Info = kicsCounters.SeverityCounters.Where(x => x.Severity == Services.ResultsSummary.SeverityEnum.INFO).Sum(x => x.Counter);
            model.ToVerify = kicsCounters.StateCounters.Where(x => x.State == ResultsSummaryState.TO_VERIFY).Sum(x => x.Counter);
            model.Total = kicsCounters.TotalCounter;
        }


        private List<Checkmarx.API.AST.Services.SASTResults.SASTResult> _sastVulnerabilities;
        public List<Checkmarx.API.AST.Services.SASTResults.SASTResult> SASTVulnerabilities
        {
            get
            {
                if (_sastVulnerabilities == null)
                    _sastVulnerabilities = _client.GetSASTScanResultsById(Id).ToList();

                return _sastVulnerabilities;
            }
        }

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
