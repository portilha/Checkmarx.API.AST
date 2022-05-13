namespace Checkmarx.API.AST.Models.Report
{
    using System;
    using System.Collections.Generic;

    using System.Globalization;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    public partial class ReportResults
    {
        [JsonProperty("reportId")]
        public Guid ReportId { get; set; }

        [JsonProperty("reportHeader")]
        public ReportHeader ReportHeader { get; set; }

        [JsonProperty("executiveSummary")]
        public ExecutiveSummary ExecutiveSummary { get; set; }

        [JsonProperty("scanSummary")]
        public ScanSummary ScanSummary { get; set; }

        [JsonProperty("scanResults")]
        public ScanResults ScanResults { get; set; }
    }

    public partial class ExecutiveSummary
    {
        [JsonProperty("branchName")]
        public string BranchName { get; set; }

        [JsonProperty("projectName")]
        public string ProjectName { get; set; }

        [JsonProperty("engines")]
        public string[] Engines { get; set; }

        [JsonProperty("riskLevel")]
        public string RiskLevel { get; set; }

        [JsonProperty("totalVulnerabilities")]
        public long TotalVulnerabilities { get; set; }

        [JsonProperty("newVulnerabilities")]
        public long NewVulnerabilities { get; set; }

        [JsonProperty("recurrentVulnerabilities")]
        public long RecurrentVulnerabilities { get; set; }

        [JsonProperty("vulnerabilitiesPerEngine")]
        public VulnerabilitiesPerEngine VulnerabilitiesPerEngine { get; set; }

        [JsonProperty("resultsTriage")]
        public ResultsTriage ResultsTriage { get; set; }
    }

    public partial class ResultsTriage
    {
        [JsonProperty("KICS")]
        public KicsClass Kics { get; set; }

        [JsonProperty("SAST")]
        public KicsClass Sast { get; set; }

        [JsonProperty("SCA")]
        public KicsClass Sca { get; set; }
    }

    public partial class KicsClass
    {
        [JsonProperty("Confirmed")]
        public Confirmed Confirmed { get; set; }

        [JsonProperty("Not exploitable")]
        public Confirmed NotExploitable { get; set; }

        [JsonProperty("To verify")]
        public Confirmed ToVerify { get; set; }

        [JsonProperty("Urgent")]
        public Confirmed Urgent { get; set; }
    }

    public partial class Confirmed
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("amount")]
        public long Amount { get; set; }

        [JsonProperty("percentage")]
        public long Percentage { get; set; }
    }

    public partial class VulnerabilitiesPerEngine
    {
        [JsonProperty("KICS")]
        public long Kics { get; set; }

        [JsonProperty("SAST")]
        public long Sast { get; set; }

        [JsonProperty("SCA")]
        public long Sca { get; set; }
    }

    public partial class ReportHeader
    {
        [JsonProperty("projectName")]
        public string ProjectName { get; set; }

        [JsonProperty("createdDate")]
        public DateTimeOffset CreatedDate { get; set; }

        [JsonProperty("tenantId")]
        public Guid TenantId { get; set; }
    }

    public partial class ScanResults
    {
        [JsonProperty("sast")]
        public Sast Sast { get; set; }

        [JsonProperty("sca")]
        public Sca Sca { get; set; }

        [JsonProperty("kics")]
        public ScanResultsKics Kics { get; set; }

        [JsonProperty("categories")]
        public object Categories { get; set; }
    }

    public partial class ScanResultsKics
    {
        [JsonProperty("results")]
        public Result[] Results { get; set; }

        [JsonProperty("vulnerabilities")]
        public Vulnerabilities Vulnerabilities { get; set; }
    }

    public partial class Result
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("vulnerabilities")]
        public ResultVulnerability[] Vulnerabilities { get; set; }

        [JsonProperty("vulnerabilitiesTotal")]
        public long VulnerabilitiesTotal { get; set; }
    }

    public partial class ResultVulnerability
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("similarityId")]
        public string SimilarityId { get; set; }

        [JsonProperty("status")]
        public string Status { get; set; }
        //public Status Status { get; set; }

        [JsonProperty("state")]
        public string State { get; set; }
        //public State State { get; set; }

        [JsonProperty("severity")]
        public string Severity { get; set; }
        //public Severity Severity { get; set; }

        [JsonProperty("firstScanId")]
        public Guid FirstScanId { get; set; }

        [JsonProperty("foundDate")]
        public DateTimeOffset FoundDate { get; set; }

        [JsonProperty("firstFoundDate")]
        public DateTimeOffset FirstFoundDate { get; set; }

        [JsonProperty("fileName")]
        public string FileName { get; set; }
        //public VulnerabilityFileName FileName { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("queryName")]
        public string QueryName { get; set; }

        [JsonProperty("expectedValue")]
        public string ExpectedValue { get; set; }

        [JsonProperty("actualValue")]
        public string ActualValue { get; set; }

        [JsonProperty("issueType")]
        public string IssueType { get; set; }
        //public IssueType IssueType { get; set; }

        [JsonProperty("category")]
        public string Category { get; set; }
        //public Category Category { get; set; }
    }

    public partial class Vulnerabilities
    {
        [JsonProperty("total")]
        public long Total { get; set; }

        [JsonProperty("high")]
        public long High { get; set; }

        [JsonProperty("medium")]
        public long Medium { get; set; }

        [JsonProperty("low")]
        public long Low { get; set; }

        [JsonProperty("info")]
        public long Info { get; set; }
    }

    public partial class Sast
    {
        [JsonProperty("languages")]
        public Language[] Languages { get; set; }

        [JsonProperty("vulnerabilities")]
        public Vulnerabilities Vulnerabilities { get; set; }
    }

    public partial class Language
    {
        [JsonProperty("languageName")]
        public string LanguageName { get; set; }

        [JsonProperty("queries")]
        public Query[] Queries { get; set; }
    }

    public partial class Query
    {
        [JsonProperty("queryName")]
        public string QueryName { get; set; }

        [JsonProperty("queryId")]
        public string QueryId { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("vulnerabilitiesTotal")]
        public long VulnerabilitiesTotal { get; set; }

        [JsonProperty("vulnerabilities")]
        public QueryVulnerability[] Vulnerabilities { get; set; }
    }

    public partial class QueryVulnerability
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("similarityId")]
        public long SimilarityId { get; set; }

        [JsonProperty("status")]
        public string Status { get; set; }
        //public Status Status { get; set; }

        [JsonProperty("state")]
        public string State { get; set; }
        //public State State { get; set; }

        [JsonProperty("severity")]
        public string Severity { get; set; }
        //public Severity Severity { get; set; }

        [JsonProperty("groupName")]
        public string GroupName { get; set; }
        //public GroupName GroupName { get; set; }

        [JsonProperty("cweId")]
        public long CweId { get; set; }

        [JsonProperty("confidenceLevel")]
        public long ConfidenceLevel { get; set; }

        [JsonProperty("compliance")]
        public string[] Compliance { get; set; }
        //public Compliance[] Compliance { get; set; }

        [JsonProperty("firstScanId")]
        public Guid FirstScanId { get; set; }

        [JsonProperty("nodes")]
        public Node[] Nodes { get; set; }

        [JsonProperty("foundDate")]
        public DateTimeOffset FoundDate { get; set; }

        [JsonProperty("firstFoundDate")]
        public DateTimeOffset FirstFoundDate { get; set; }
    }

    public partial class Node
    {
        [JsonProperty("column")]
        public long Column { get; set; }

        [JsonProperty("fileName")]
        public string FileName { get; set; }
        //public NodeFileName FileName { get; set; }

        [JsonProperty("fullName")]
        public string FullName { get; set; }

        [JsonProperty("length")]
        public long Length { get; set; }

        [JsonProperty("line")]
        public long Line { get; set; }

        [JsonProperty("methodLine")]
        public long MethodLine { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("domType")]
        public string DomType { get; set; }
        //public DomType DomType { get; set; }

        [JsonProperty("method")]
        public string Method { get; set; }
    }

    public partial class Sca
    {
        [JsonProperty("packagesCount")]
        public long PackagesCount { get; set; }

        [JsonProperty("packages")]
        public Package[] Packages { get; set; }

        [JsonProperty("vulnerabilities")]
        public Vulnerabilities Vulnerabilities { get; set; }
    }

    public partial class Package
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("vulnerabilities")]
        public PackageVulnerability[] Vulnerabilities { get; set; }
    }

    public partial class PackageVulnerability
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("similarityId")]
        public string SimilarityId { get; set; }

        [JsonProperty("version")]
        public string Version { get; set; }

        [JsonProperty("riskLevel")]
        public string RiskLevel { get; set; }
        //public Severity RiskLevel { get; set; }

        [JsonProperty("severity")]
        public string Severity { get; set; }
        //public Severity Severity { get; set; }

        [JsonProperty("outdated")]
        public bool Outdated { get; set; }

        [JsonProperty("firstScanId")]
        public Guid FirstScanId { get; set; }

        [JsonProperty("status")]
        public string Status { get; set; }
        //public Status Status { get; set; }

        [JsonProperty("state")]
        public string State { get; set; }
        //public State State { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("cveId")]
        public string CveId { get; set; }

        [JsonProperty("cveName")]
        public string CveName { get; set; }

        [JsonProperty("cwe")]
        public string Cwe { get; set; }

        [JsonProperty("foundDate")]
        public DateTimeOffset FoundDate { get; set; }

        [JsonProperty("firstFoundDate")]
        public DateTimeOffset FirstFoundDate { get; set; }
    }

    public partial class ScanSummary
    {
        [JsonProperty("scanId")]
        public Guid ScanId { get; set; }

        [JsonProperty("languages")]
        public string[] Languages { get; set; }

        [JsonProperty("enginesCount")]
        public long EnginesCount { get; set; }

        [JsonProperty("scanCompletedDate")]
        public string ScanCompletedDate { get; set; }

        [JsonProperty("engineTypes")]
        public string[] EngineTypes { get; set; }
    }

    //public enum Category { AccessControl, BestPractices, BuildProcess, InsecureConfigurations, NetworkingAndFirewall, Observability, SupplyChain };

    //public enum VulnerabilityFileName { Dockerfile, TerraformExamplesNegative1Tf, TerraformExamplesNegative2Tf, TerraformExamplesPositive1Tf, TerraformExamplesPositive2Tf };

    //public enum IssueType { IncorrectValue, MissingAttribute };

    //public enum Severity { High, Info, Low, Medium };

    //public enum State { ProposedNotExploitable, ToVerify };

    //public enum Status { Recurrent };

    //public enum Compliance { AsdStig410, Fisma2014, NistSp80053, OwaspMobileTop102016, OwaspTop102013, OwaspTop102017, OwaspTop102021, OwaspTop10Api, PciDssV321 };

    //public enum GroupName { JavaHighRisk };

    //public enum DomType { Declarator, MethodInvokeExpr, ParamDecl, StringLiteral, UnknownReference };

    //public enum NodeFileName { SrcLoginJava, SrcXssJava, TestBJava };

    //internal static class Converter
    //{
    //    public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
    //    {
    //        MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
    //        DateParseHandling = DateParseHandling.None,
    //        Converters =
    //        {
    //            CategoryConverter.Singleton,
    //            VulnerabilityFileNameConverter.Singleton,
    //            IssueTypeConverter.Singleton,
    //            SeverityConverter.Singleton,
    //            StateConverter.Singleton,
    //            StatusConverter.Singleton,
    //            ComplianceConverter.Singleton,
    //            GroupNameConverter.Singleton,
    //            DomTypeConverter.Singleton,
    //            NodeFileNameConverter.Singleton,
    //            new IsoDateTimeConverter { DateTimeStyles = DateTimeStyles.AssumeUniversal }
    //        },
    //    };
    //}

    //internal class CategoryConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(Category) || t == typeof(Category?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        switch (value)
    //        {
    //            case "Access Control":
    //                return Category.AccessControl;
    //            case "Best Practices":
    //                return Category.BestPractices;
    //            case "Build Process":
    //                return Category.BuildProcess;
    //            case "Insecure Configurations":
    //                return Category.InsecureConfigurations;
    //            case "Networking and Firewall":
    //                return Category.NetworkingAndFirewall;
    //            case "Observability":
    //                return Category.Observability;
    //            case "Supply-Chain":
    //                return Category.SupplyChain;
    //        }
    //        throw new Exception("Cannot unmarshal type Category");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (Category)untypedValue;
    //        switch (value)
    //        {
    //            case Category.AccessControl:
    //                serializer.Serialize(writer, "Access Control");
    //                return;
    //            case Category.BestPractices:
    //                serializer.Serialize(writer, "Best Practices");
    //                return;
    //            case Category.BuildProcess:
    //                serializer.Serialize(writer, "Build Process");
    //                return;
    //            case Category.InsecureConfigurations:
    //                serializer.Serialize(writer, "Insecure Configurations");
    //                return;
    //            case Category.NetworkingAndFirewall:
    //                serializer.Serialize(writer, "Networking and Firewall");
    //                return;
    //            case Category.Observability:
    //                serializer.Serialize(writer, "Observability");
    //                return;
    //            case Category.SupplyChain:
    //                serializer.Serialize(writer, "Supply-Chain");
    //                return;
    //        }
    //        throw new Exception("Cannot marshal type Category");
    //    }

    //    public static readonly CategoryConverter Singleton = new CategoryConverter();
    //}

    //internal class VulnerabilityFileNameConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(VulnerabilityFileName) || t == typeof(VulnerabilityFileName?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        switch (value)
    //        {
    //            case "/Dockerfile":
    //                return VulnerabilityFileName.Dockerfile;
    //            case "/terraform_examples/negative1.tf":
    //                return VulnerabilityFileName.TerraformExamplesNegative1Tf;
    //            case "/terraform_examples/negative2.tf":
    //                return VulnerabilityFileName.TerraformExamplesNegative2Tf;
    //            case "/terraform_examples/positive1.tf":
    //                return VulnerabilityFileName.TerraformExamplesPositive1Tf;
    //            case "/terraform_examples/positive2.tf":
    //                return VulnerabilityFileName.TerraformExamplesPositive2Tf;
    //        }
    //        throw new Exception("Cannot unmarshal type VulnerabilityFileName");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (VulnerabilityFileName)untypedValue;
    //        switch (value)
    //        {
    //            case VulnerabilityFileName.Dockerfile:
    //                serializer.Serialize(writer, "/Dockerfile");
    //                return;
    //            case VulnerabilityFileName.TerraformExamplesNegative1Tf:
    //                serializer.Serialize(writer, "/terraform_examples/negative1.tf");
    //                return;
    //            case VulnerabilityFileName.TerraformExamplesNegative2Tf:
    //                serializer.Serialize(writer, "/terraform_examples/negative2.tf");
    //                return;
    //            case VulnerabilityFileName.TerraformExamplesPositive1Tf:
    //                serializer.Serialize(writer, "/terraform_examples/positive1.tf");
    //                return;
    //            case VulnerabilityFileName.TerraformExamplesPositive2Tf:
    //                serializer.Serialize(writer, "/terraform_examples/positive2.tf");
    //                return;
    //        }
    //        throw new Exception("Cannot marshal type VulnerabilityFileName");
    //    }

    //    public static readonly VulnerabilityFileNameConverter Singleton = new VulnerabilityFileNameConverter();
    //}

    //internal class IssueTypeConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(IssueType) || t == typeof(IssueType?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        switch (value)
    //        {
    //            case "IncorrectValue":
    //                return IssueType.IncorrectValue;
    //            case "MissingAttribute":
    //                return IssueType.MissingAttribute;
    //        }
    //        throw new Exception("Cannot unmarshal type IssueType");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (IssueType)untypedValue;
    //        switch (value)
    //        {
    //            case IssueType.IncorrectValue:
    //                serializer.Serialize(writer, "IncorrectValue");
    //                return;
    //            case IssueType.MissingAttribute:
    //                serializer.Serialize(writer, "MissingAttribute");
    //                return;
    //        }
    //        throw new Exception("Cannot marshal type IssueType");
    //    }

    //    public static readonly IssueTypeConverter Singleton = new IssueTypeConverter();
    //}

    //internal class SeverityConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(Severity) || t == typeof(Severity?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        switch (value)
    //        {
    //            case "HIGH":
    //                return Severity.High;
    //            case "INFO":
    //                return Severity.Info;
    //            case "LOW":
    //                return Severity.Low;
    //            case "MEDIUM":
    //                return Severity.Medium;
    //        }
    //        throw new Exception("Cannot unmarshal type Severity");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (Severity)untypedValue;
    //        switch (value)
    //        {
    //            case Severity.High:
    //                serializer.Serialize(writer, "HIGH");
    //                return;
    //            case Severity.Info:
    //                serializer.Serialize(writer, "INFO");
    //                return;
    //            case Severity.Low:
    //                serializer.Serialize(writer, "LOW");
    //                return;
    //            case Severity.Medium:
    //                serializer.Serialize(writer, "MEDIUM");
    //                return;
    //        }
    //        throw new Exception("Cannot marshal type Severity");
    //    }

    //    public static readonly SeverityConverter Singleton = new SeverityConverter();
    //}

    //internal class StateConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(State) || t == typeof(State?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        switch (value)
    //        {
    //            case "Proposed not exploitable":
    //                return State.ProposedNotExploitable;
    //            case "To verify":
    //                return State.ToVerify;
    //        }
    //        throw new Exception("Cannot unmarshal type State");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (State)untypedValue;
    //        switch (value)
    //        {
    //            case State.ProposedNotExploitable:
    //                serializer.Serialize(writer, "Proposed not exploitable");
    //                return;
    //            case State.ToVerify:
    //                serializer.Serialize(writer, "To verify");
    //                return;
    //        }
    //        throw new Exception("Cannot marshal type State");
    //    }

    //    public static readonly StateConverter Singleton = new StateConverter();
    //}

    //internal class StatusConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(Status) || t == typeof(Status?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        if (value == "RECURRENT")
    //        {
    //            return Status.Recurrent;
    //        }
    //        throw new Exception("Cannot unmarshal type Status");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (Status)untypedValue;
    //        if (value == Status.Recurrent)
    //        {
    //            serializer.Serialize(writer, "RECURRENT");
    //            return;
    //        }
    //        throw new Exception("Cannot marshal type Status");
    //    }

    //    public static readonly StatusConverter Singleton = new StatusConverter();
    //}

    //internal class ComplianceConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(Compliance) || t == typeof(Compliance?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        switch (value)
    //        {
    //            case "ASD STIG 4.10":
    //                return Compliance.AsdStig410;
    //            case "FISMA 2014":
    //                return Compliance.Fisma2014;
    //            case "NIST SP 800-53":
    //                return Compliance.NistSp80053;
    //            case "OWASP Mobile Top 10 2016":
    //                return Compliance.OwaspMobileTop102016;
    //            case "OWASP Top 10 2013":
    //                return Compliance.OwaspTop102013;
    //            case "OWASP Top 10 2017":
    //                return Compliance.OwaspTop102017;
    //            case "OWASP Top 10 2021":
    //                return Compliance.OwaspTop102021;
    //            case "OWASP Top 10 API":
    //                return Compliance.OwaspTop10Api;
    //            case "PCI DSS v3.2.1":
    //                return Compliance.PciDssV321;
    //        }
    //        throw new Exception("Cannot unmarshal type Compliance");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (Compliance)untypedValue;
    //        switch (value)
    //        {
    //            case Compliance.AsdStig410:
    //                serializer.Serialize(writer, "ASD STIG 4.10");
    //                return;
    //            case Compliance.Fisma2014:
    //                serializer.Serialize(writer, "FISMA 2014");
    //                return;
    //            case Compliance.NistSp80053:
    //                serializer.Serialize(writer, "NIST SP 800-53");
    //                return;
    //            case Compliance.OwaspMobileTop102016:
    //                serializer.Serialize(writer, "OWASP Mobile Top 10 2016");
    //                return;
    //            case Compliance.OwaspTop102013:
    //                serializer.Serialize(writer, "OWASP Top 10 2013");
    //                return;
    //            case Compliance.OwaspTop102017:
    //                serializer.Serialize(writer, "OWASP Top 10 2017");
    //                return;
    //            case Compliance.OwaspTop102021:
    //                serializer.Serialize(writer, "OWASP Top 10 2021");
    //                return;
    //            case Compliance.OwaspTop10Api:
    //                serializer.Serialize(writer, "OWASP Top 10 API");
    //                return;
    //            case Compliance.PciDssV321:
    //                serializer.Serialize(writer, "PCI DSS v3.2.1");
    //                return;
    //        }
    //        throw new Exception("Cannot marshal type Compliance");
    //    }

    //    public static readonly ComplianceConverter Singleton = new ComplianceConverter();
    //}

    //internal class GroupNameConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(GroupName) || t == typeof(GroupName?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        if (value == "Java_High_Risk")
    //        {
    //            return GroupName.JavaHighRisk;
    //        }
    //        throw new Exception("Cannot unmarshal type GroupName");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (GroupName)untypedValue;
    //        if (value == GroupName.JavaHighRisk)
    //        {
    //            serializer.Serialize(writer, "Java_High_Risk");
    //            return;
    //        }
    //        throw new Exception("Cannot marshal type GroupName");
    //    }

    //    public static readonly GroupNameConverter Singleton = new GroupNameConverter();
    //}

    //internal class DomTypeConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(DomType) || t == typeof(DomType?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        switch (value)
    //        {
    //            case "Declarator":
    //                return DomType.Declarator;
    //            case "MethodInvokeExpr":
    //                return DomType.MethodInvokeExpr;
    //            case "ParamDecl":
    //                return DomType.ParamDecl;
    //            case "StringLiteral":
    //                return DomType.StringLiteral;
    //            case "UnknownReference":
    //                return DomType.UnknownReference;
    //        }
    //        throw new Exception("Cannot unmarshal type DomType");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (DomType)untypedValue;
    //        switch (value)
    //        {
    //            case DomType.Declarator:
    //                serializer.Serialize(writer, "Declarator");
    //                return;
    //            case DomType.MethodInvokeExpr:
    //                serializer.Serialize(writer, "MethodInvokeExpr");
    //                return;
    //            case DomType.ParamDecl:
    //                serializer.Serialize(writer, "ParamDecl");
    //                return;
    //            case DomType.StringLiteral:
    //                serializer.Serialize(writer, "StringLiteral");
    //                return;
    //            case DomType.UnknownReference:
    //                serializer.Serialize(writer, "UnknownReference");
    //                return;
    //        }
    //        throw new Exception("Cannot marshal type DomType");
    //    }

    //    public static readonly DomTypeConverter Singleton = new DomTypeConverter();
    //}

    //internal class NodeFileNameConverter : JsonConverter
    //{
    //    public override bool CanConvert(Type t) => t == typeof(NodeFileName) || t == typeof(NodeFileName?);

    //    public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
    //    {
    //        if (reader.TokenType == JsonToken.Null) return null;
    //        var value = serializer.Deserialize<string>(reader);
    //        switch (value)
    //        {
    //            case "/src/Login.java":
    //                return NodeFileName.SrcLoginJava;
    //            case "/src/xss.java":
    //                return NodeFileName.SrcXssJava;
    //            case "/test/b.java":
    //                return NodeFileName.TestBJava;
    //        }
    //        throw new Exception("Cannot unmarshal type NodeFileName");
    //    }

    //    public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
    //    {
    //        if (untypedValue == null)
    //        {
    //            serializer.Serialize(writer, null);
    //            return;
    //        }
    //        var value = (NodeFileName)untypedValue;
    //        switch (value)
    //        {
    //            case NodeFileName.SrcLoginJava:
    //                serializer.Serialize(writer, "/src/Login.java");
    //                return;
    //            case NodeFileName.SrcXssJava:
    //                serializer.Serialize(writer, "/src/xss.java");
    //                return;
    //            case NodeFileName.TestBJava:
    //                serializer.Serialize(writer, "/test/b.java");
    //                return;
    //        }
    //        throw new Exception("Cannot marshal type NodeFileName");
    //    }

    //    public static readonly NodeFileNameConverter Singleton = new NodeFileNameConverter();
    //}

    internal class ParseStringConverter : JsonConverter
    {
        public override bool CanConvert(Type t) => t == typeof(long) || t == typeof(long?);

        public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null) return null;
            var value = serializer.Deserialize<string>(reader);
            long l;
            if (Int64.TryParse(value, out l))
            {
                return l;
            }
            throw new Exception("Cannot unmarshal type long");
        }

        public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer)
        {
            if (untypedValue == null)
            {
                serializer.Serialize(writer, null);
                return;
            }
            var value = (long)untypedValue;
            serializer.Serialize(writer, value.ToString());
            return;
        }

        public static readonly ParseStringConverter Singleton = new ParseStringConverter();
    }
}
