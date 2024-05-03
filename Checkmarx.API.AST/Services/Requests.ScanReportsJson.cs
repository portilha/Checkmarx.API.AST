using System;
using System.Collections.Generic;

using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Checkmarx.API.AST.Services
{
    public partial class ScanReportJson
    {
        [JsonProperty("RiskReportSummary", NullValueHandling = NullValueHandling.Ignore)]
        public RiskReportSummary RiskReportSummary { get; set; }

        [JsonProperty("Packages", NullValueHandling = NullValueHandling.Ignore)]
        public List<Package> Packages { get; set; }

        [JsonProperty("Licenses", NullValueHandling = NullValueHandling.Ignore)]
        public List<License> Licenses { get; set; }

        [JsonProperty("Vulnerabilities", NullValueHandling = NullValueHandling.Ignore)]
        public List<Vulnerability> Vulnerabilities { get; set; }

        [JsonProperty("Policies", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> Policies { get; set; }
    }

    public partial class License
    {
        [JsonProperty("ReferenceType", NullValueHandling = NullValueHandling.Ignore)]
        public string ReferenceType { get; set; }

        [JsonProperty("Reference", NullValueHandling = NullValueHandling.Ignore)]
        public Uri Reference { get; set; }

        [JsonProperty("CopyrightRiskScore", NullValueHandling = NullValueHandling.Ignore)]
        public long? CopyrightRiskScore { get; set; }

        [JsonProperty("RiskLevel", NullValueHandling = NullValueHandling.Ignore)]
        public string RiskLevel { get; set; }

        [JsonProperty("CopyLeft", NullValueHandling = NullValueHandling.Ignore)]
        public string CopyLeft { get; set; }

        [JsonProperty("PatentRiskScore", NullValueHandling = NullValueHandling.Ignore)]
        public long? PatentRiskScore { get; set; }

        [JsonProperty("Name", NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }

        [JsonProperty("Url", NullValueHandling = NullValueHandling.Ignore)]
        public string Url { get; set; }

        [JsonProperty("PackageUsageCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? PackageUsageCount { get; set; }

        [JsonProperty("IsViolatingPolicy", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsViolatingPolicy { get; set; }

        [JsonProperty("RoyaltyFree", NullValueHandling = NullValueHandling.Ignore)]
        public string RoyaltyFree { get; set; }

        [JsonProperty("Linking", NullValueHandling = NullValueHandling.Ignore)]
        public string Linking { get; set; }
    }

    public partial class Package
    {
        [JsonProperty("Id", NullValueHandling = NullValueHandling.Ignore)]
        public string Id { get; set; }

        [JsonProperty("Name", NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }

        [JsonProperty("Version", NullValueHandling = NullValueHandling.Ignore)]
        public string Version { get; set; }

        [JsonProperty("Licenses", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Licenses { get; set; }

        [JsonProperty("MatchType", NullValueHandling = NullValueHandling.Ignore)]
        public string MatchType { get; set; }

        [JsonProperty("CriticalVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? CriticalVulnerabilityCount { get; set; }

        [JsonProperty("HighVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? HighVulnerabilityCount { get; set; }

        [JsonProperty("MediumVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? MediumVulnerabilityCount { get; set; }

        [JsonProperty("LowVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? LowVulnerabilityCount { get; set; }

        [JsonProperty("NoneVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? NoneVulnerabilityCount { get; set; }

        [JsonProperty("NumberOfVersionsSinceLastUpdate", NullValueHandling = NullValueHandling.Ignore)]
        public long? NumberOfVersionsSinceLastUpdate { get; set; }

        [JsonProperty("NewestVersionReleaseDate")]
        public string NewestVersionReleaseDate { get; set; }

        [JsonProperty("NewestVersion")]
        public string NewestVersion { get; set; }

        [JsonProperty("Outdated", NullValueHandling = NullValueHandling.Ignore)]
        public bool? Outdated { get; set; }

        [JsonProperty("ReleaseDate", NullValueHandling = NullValueHandling.Ignore)]
        public string ReleaseDate { get; set; }

        [JsonProperty("RiskScore", NullValueHandling = NullValueHandling.Ignore)]
        public double? RiskScore { get; set; }

        [JsonProperty("Severity", NullValueHandling = NullValueHandling.Ignore)]
        public string Severity { get; set; }

        [JsonProperty("Locations", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Locations { get; set; }

        [JsonProperty("PackageRepository", NullValueHandling = NullValueHandling.Ignore)]
        public string PackageRepository { get; set; }

        [JsonProperty("IsMalicious", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsMalicious { get; set; }

        [JsonProperty("IsDirectDependency", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsDirectDependency { get; set; }

        [JsonProperty("IsDevelopmentDependency", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsDevelopmentDependency { get; set; }

        [JsonProperty("IsTestDependency", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsTestDependency { get; set; }

        [JsonProperty("IsNpmVerified", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsNpmVerified { get; set; }

        [JsonProperty("IsViolatingPolicy", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsViolatingPolicy { get; set; }

        [JsonProperty("UsageType", NullValueHandling = NullValueHandling.Ignore)]
        public string UsageType { get; set; }

        [JsonProperty("VulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? VulnerabilityCount { get; set; }

        [JsonProperty("IsPrivatePackage", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsPrivatePackage { get; set; }

        [JsonProperty("PackagePaths", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> PackagePaths { get; set; }

        [JsonProperty("PackageState", NullValueHandling = NullValueHandling.Ignore)]
        public string PackageState { get; set; }

        [JsonProperty("PackageStateValue")]
        public object PackageStateValue { get; set; }

        [JsonProperty("PackageStateLastUpdateDate")]
        public object PackageStateLastUpdateDate { get; set; }

        [JsonProperty("PackageStateLastUpdateUser")]
        public object PackageStateLastUpdateUser { get; set; }

        [JsonProperty("PackageStateLastUpdateComment")]
        public object PackageStateLastUpdateComment { get; set; }
    }

    public partial class RiskReportSummary
    {
        [JsonProperty("RiskReportId", NullValueHandling = NullValueHandling.Ignore)]
        public string RiskReportId { get; set; }

        [JsonProperty("ProjectId", NullValueHandling = NullValueHandling.Ignore)]
        public string ProjectId { get; set; }

        [JsonProperty("ProjectName", NullValueHandling = NullValueHandling.Ignore)]
        public string ProjectName { get; set; }

        [JsonProperty("ProjectCreatedOn", NullValueHandling = NullValueHandling.Ignore)]
        public string ProjectCreatedOn { get; set; }

        [JsonProperty("ProjectTags", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> ProjectTags { get; set; }

        [JsonProperty("CriticalVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? CriticalVulnerabilityCount { get; set; }

        [JsonProperty("HighVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? HighVulnerabilityCount { get; set; }

        [JsonProperty("MediumVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? MediumVulnerabilityCount { get; set; }

        [JsonProperty("LowVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? LowVulnerabilityCount { get; set; }

        [JsonProperty("NoneVulnerabilityCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? NoneVulnerabilityCount { get; set; }

        [JsonProperty("TotalPackages", NullValueHandling = NullValueHandling.Ignore)]
        public long? TotalPackages { get; set; }

        [JsonProperty("DirectPackages", NullValueHandling = NullValueHandling.Ignore)]
        public long? DirectPackages { get; set; }

        [JsonProperty("CreatedOn", NullValueHandling = NullValueHandling.Ignore)]
        public string CreatedOn { get; set; }

        [JsonProperty("RiskScore", NullValueHandling = NullValueHandling.Ignore)]
        public double? RiskScore { get; set; }

        [JsonProperty("TotalOutdatedPackages", NullValueHandling = NullValueHandling.Ignore)]
        public long? TotalOutdatedPackages { get; set; }

        [JsonProperty("VulnerablePackages", NullValueHandling = NullValueHandling.Ignore)]
        public long? VulnerablePackages { get; set; }

        [JsonProperty("CriticalVulnerablePackages", NullValueHandling = NullValueHandling.Ignore)]
        public long? CriticalVulnerablePackages { get; set; }

        [JsonProperty("HighVulnerablePackages", NullValueHandling = NullValueHandling.Ignore)]
        public long? HighVulnerablePackages { get; set; }

        [JsonProperty("MediumVulnerablePackages", NullValueHandling = NullValueHandling.Ignore)]
        public long? MediumVulnerablePackages { get; set; }

        [JsonProperty("LowVulnerablePackages", NullValueHandling = NullValueHandling.Ignore)]
        public long? LowVulnerablePackages { get; set; }

        [JsonProperty("NoneVulnerablePackages", NullValueHandling = NullValueHandling.Ignore)]
        public long? NoneVulnerablePackages { get; set; }

        [JsonProperty("TotalPackagesWithLegalRisk", NullValueHandling = NullValueHandling.Ignore)]
        public long? TotalPackagesWithLegalRisk { get; set; }

        [JsonProperty("LicensesLegalRisk", NullValueHandling = NullValueHandling.Ignore)]
        public LicensesLegalRisk LicensesLegalRisk { get; set; }

        [JsonProperty("ScanOrigin", NullValueHandling = NullValueHandling.Ignore)]
        public string ScanOrigin { get; set; }

        [JsonProperty("ScanTags", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> ScanTags { get; set; }

        [JsonProperty("ExploitablePathEnabled", NullValueHandling = NullValueHandling.Ignore)]
        public bool? ExploitablePathEnabled { get; set; }

        [JsonProperty("ExploitablePathsFound", NullValueHandling = NullValueHandling.Ignore)]
        public long? ExploitablePathsFound { get; set; }

        [JsonProperty("HasRemediationRecommendation", NullValueHandling = NullValueHandling.Ignore)]
        public bool? HasRemediationRecommendation { get; set; }

        [JsonProperty("BuildBreakerPolicies", NullValueHandling = NullValueHandling.Ignore)]
        public long? BuildBreakerPolicies { get; set; }

        [JsonProperty("ProjectPolicies", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> ProjectPolicies { get; set; }

        [JsonProperty("ViolatingPoliciesCount", NullValueHandling = NullValueHandling.Ignore)]
        public long? ViolatingPoliciesCount { get; set; }
    }

    public partial class LicensesLegalRisk
    {
        [JsonProperty("Critical", NullValueHandling = NullValueHandling.Ignore)]
        public long? Critical { get; set; }

        [JsonProperty("High", NullValueHandling = NullValueHandling.Ignore)]
        public long? High { get; set; }

        [JsonProperty("Medium", NullValueHandling = NullValueHandling.Ignore)]
        public long? Medium { get; set; }

        [JsonProperty("Low", NullValueHandling = NullValueHandling.Ignore)]
        public long? Low { get; set; }

        [JsonProperty("None", NullValueHandling = NullValueHandling.Ignore)]
        public long? None { get; set; }
    }

    public partial class Vulnerability
    {
        [JsonProperty("Id", NullValueHandling = NullValueHandling.Ignore)]
        public string Id { get; set; }

        [JsonProperty("CveName", NullValueHandling = NullValueHandling.Ignore)]
        public string CveName { get; set; }

        [JsonProperty("Score", NullValueHandling = NullValueHandling.Ignore)]
        public double? Score { get; set; }

        [JsonProperty("Severity", NullValueHandling = NullValueHandling.Ignore)]
        public string Severity { get; set; }

        [JsonProperty("PublishDate", NullValueHandling = NullValueHandling.Ignore)]
        public DateTimeOffset? PublishDate { get; set; }

        [JsonProperty("References", NullValueHandling = NullValueHandling.Ignore)]
        public List<Uri> References { get; set; }

        [JsonProperty("Description", NullValueHandling = NullValueHandling.Ignore)]
        public string Description { get; set; }

        [JsonProperty("Cvss2")]
        public Dictionary<string, string> Cvss2 { get; set; }

        [JsonProperty("Cvss3", NullValueHandling = NullValueHandling.Ignore)]
        public Dictionary<string, string> Cvss3 { get; set; }

        [JsonProperty("PackageId", NullValueHandling = NullValueHandling.Ignore)]
        public string PackageId { get; set; }

        [JsonProperty("PackageName", NullValueHandling = NullValueHandling.Ignore)]
        public string PackageName { get; set; }

        [JsonProperty("PackageVersion", NullValueHandling = NullValueHandling.Ignore)]
        public string PackageVersion { get; set; }

        [JsonProperty("PackageManager", NullValueHandling = NullValueHandling.Ignore)]
        public string PackageManager { get; set; }

        [JsonProperty("FixResolutionText")]
        public string FixResolutionText { get; set; }

        [JsonProperty("IsIgnored", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsIgnored { get; set; }

        [JsonProperty("RiskState", NullValueHandling = NullValueHandling.Ignore)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public VulnerabilityStatus RiskState { get; set; }

        [JsonProperty("RiskStateLastUpdateDate")]
        public DateTimeOffset? RiskStateLastUpdateDate { get; set; }

        [JsonProperty("RiskStateLastUpdateUser")]
        public string RiskStateLastUpdateUser { get; set; }

        [JsonProperty("RiskStateLastUpdateComment")]
        public string RiskStateLastUpdateComment { get; set; }

        [JsonProperty("RiskStatus", NullValueHandling = NullValueHandling.Ignore)]
        public string RiskStatus { get; set; }

        [JsonProperty("FirstFoundAt", NullValueHandling = NullValueHandling.Ignore)]
        public DateTimeOffset? FirstFoundAt { get; set; }

        [JsonProperty("Kev", NullValueHandling = NullValueHandling.Ignore)]
        public bool? Kev { get; set; }

        [JsonProperty("Poc", NullValueHandling = NullValueHandling.Ignore)]
        public bool? Poc { get; set; }

        [JsonProperty("Epss", NullValueHandling = NullValueHandling.Ignore)]
        public bool? Epss { get; set; }

        [JsonProperty("EpssValue")]
        public double? EpssValue { get; set; }

        [JsonProperty("EpssPercentile")]
        public double? EpssPercentile { get; set; }

        [JsonProperty("ExploitablePath", NullValueHandling = NullValueHandling.Ignore)]
        public bool? ExploitablePath { get; set; }

        [JsonProperty("ExploitableMethods", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> ExploitableMethods { get; set; }

        [JsonProperty("Cwe", NullValueHandling = NullValueHandling.Ignore)]
        public string Cwe { get; set; }

        [JsonProperty("IsViolatingPolicy", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IsViolatingPolicy { get; set; }

        [JsonProperty("Type", NullValueHandling = NullValueHandling.Ignore)]
        public string Type { get; set; }
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


