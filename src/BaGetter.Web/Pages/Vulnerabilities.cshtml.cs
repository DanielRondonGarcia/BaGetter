using System;
using System.Globalization;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BaGetter.Authentication;
using BaGetter.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NuGet.Versioning;

namespace BaGetter.Web;

/// <summary>
/// The global vulnerability dashboard. It shows the real, current snapshot
/// produced by <see cref="HostedVulnerabilityService"/> and lets operators
/// trigger an explicit rescan. A regular GET only reads the last snapshot —
/// it never starts a scan; scans run automatically in the background (hourly)
/// or when the Rescan form is submitted (with antiforgery protection).
///
/// The page also exports the archived analysis history (T7) as a CSV
/// download: <c>GET /vulnerabilities?handler=ExportCsv</c> with an inclusive
/// UTC date range and optional package/version filters. The live analysis
/// itself is never modified by an export.
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.NugetBasicAuthenticationScheme, Policy = AuthenticationConstants.NugetUserPolicy)]
public class VulnerabilitiesModel : PageModel
{
    /// <summary>
    /// The default (and fallback) number of package groups per page. Optional
    /// pageSize query values may raise the effective size up to the 1000 cap.
    /// </summary>
    public const int PackagePageSize = 50;

    /// <summary>
    /// The effective package-group page size for this request, after the
    /// optional pageSize query is normalized (default 50, cap 1000, nonpositive
    /// falls back to 50). The view, selector and navigation links always use
    /// this value, so "page of N" and the selected option stay truthful.
    /// </summary>
    public int EffectivePackagePageSize { get; private set; } = PackagePageSize;

    /// <summary>
    /// Whether the effective size is one of the preset selector options; a
    /// positive nonpreset value (like 75) is still honored and shown as a
    /// transient selected option.
    /// </summary>
    public bool EffectivePageSizeIsPreset =>
        Array.IndexOf(PageSizeOptions, EffectivePackagePageSize) >= 0;

    private readonly HostedVulnerabilityService _scanner;
    private readonly VulnerabilityHistoryStore _historyStore;
    private readonly VulnerabilityCsvExporter _csvExporter;

    /// <summary>
    /// The history store is optional so original single-service constructor
    /// callers keep working; the exporter is optional for the same reason.
    /// </summary>
    public VulnerabilitiesModel(
        HostedVulnerabilityService scanner,
        VulnerabilityHistoryStore historyStore = null,
        VulnerabilityCsvExporter csvExporter = null)
    {
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
        _historyStore = historyStore;
        _csvExporter = csvExporter;
    }

    /// <summary>The latest stable snapshot (never null).</summary>
    public HostedVulnerabilitySnapshot Snapshot { get; private set; }

    /// <summary>
    /// The lifecycle state including the transient "Scanning" state while a
    /// refresh is running.
    /// </summary>
    public HostedVulnerabilityStatus EffectiveStatus { get; private set; }

    /// <summary>
    /// The history archive's status as seen by this render (null when no
    /// history store is available).
    /// </summary>
    public VulnerabilityHistoryStatusInfo ExportStatus { get; private set; }

    /// <summary>
    /// Prefilled export form values: the requested package ID/version from a
    /// query parameter (for example from a package page's export link).
    /// </summary>
    public string ExportPackageId { get; private set; }

    public string ExportVersion { get; private set; }

    /// <summary>Today's UTC date, the default "from"/"to" for the export form.</summary>
    public string ExportTodayUtc =>
        DateTime.UtcNow.Date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    /// <summary>
    /// The selectable package page sizes (labels for the Apply form). The
    /// default is <see cref="PackagePageSize"/>; any positive nonpreset value
    /// is honored truthfully up to the 1000 cap.
    /// </summary>
    public static readonly int[] PageSizeOptions = { 50, 100, 250, 500, 1000 };

    public void OnGet(string exportPackageId = null, string exportVersion = null, int pageNumber = 1, int pageSize = 0)
    {
        Snapshot = _scanner.Current;
        EffectiveStatus = _scanner.Status;
        ExportPackageId = exportPackageId;
        ExportVersion = exportVersion;
        ExportStatus = _historyStore?.GetStatus();

        // The pagination unit is the case-insensitive package ID (T1), not the
        // ID + version row: a package with many versions is ONE summary row on
        // exactly one page, and its details load lazily when expanded instead
        // of being embedded (or paginated away) per version.
        var packageGroups = Snapshot.Packages
            .GroupBy(package => package.PackageId, StringComparer.OrdinalIgnoreCase)
            .Select(group => new PackageVulnerabilityGroup(group.Key, group.ToList()))
            .ToList();

        // T2/S3: optional pageSize. Absent/nonpositive input falls back to the
        // default; positive values are honored up to the 1000 cap, and the
        // effective (normalized) size is what the view and links reflect.
        EffectivePackagePageSize = NormalizePageSize(pageSize);

        // GroupBy preserves first-seen order, so scan ordering is unchanged.
        TotalPackageGroupCount = packageGroups.Count;
        TotalPackagePages = (TotalPackageGroupCount + EffectivePackagePageSize - 1) / EffectivePackagePageSize;
        PackagePageNumber = Math.Max(1, Math.Min(pageNumber, Math.Max(1, TotalPackagePages)));
        PackageGroups = packageGroups
            .Skip((PackagePageNumber - 1) * EffectivePackagePageSize)
            .Take(EffectivePackagePageSize)
            .ToList();
    }

    private static int NormalizePageSize(int requestedSize)
    {
        if (requestedSize < 1)
        {
            return PackagePageSize;
        }

        return Math.Min(requestedSize, 1000);
    }

    /// <summary>
    /// The lazy details fragment for one selected package (T1): an explicit
    /// <c>GET ?handler=PackageDetails&amp;packageId=&lt;ID&gt;</c> on this same
    /// Razor Page. It inherits the page's NuGet read authorization, renders the
    /// server-escaped <c>_VulnerabilityPackageVersions</c> partial from the
    /// immutable <c>Current</c> snapshot, and never mutates scan state, contacts
    /// the feed or changes counters. Empty IDs are 400; unmatched IDs (matched
    /// case-insensitively, never partially) are 404. The response is marked
    /// no-store so a stale dashboard never serves cached fragments.
    /// </summary>
    public IActionResult OnGetPackageDetails(string packageId)
    {
        // Guard for direct unit tests without a host context.
        var responseHeaders = Response?.Headers;
        if (responseHeaders != null)
        {
            responseHeaders["Cache-Control"] = "no-store";
        }

        if (string.IsNullOrWhiteSpace(packageId))
        {
            return PlainText(
                400,
                "The package details request is invalid: a package ID is required.");
        }

        Snapshot = _scanner.Current;
        var versions = Snapshot.Packages
            .Where(package => string.Equals(
                package.PackageId, packageId.Trim(), StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (versions.Count == 0)
        {
            return PlainText(
                404,
                "No hosted package matches the requested ID. Package IDs are matched " +
                "case-insensitively and exactly (not partially); the package may not " +
                "be hosted here.");
        }

        // The fragment carries the stored, case-preserved ID so package-page
        // links stay canonical even when the request used another casing.
        return Partial("_VulnerabilityPackageVersions",
            new PackageVulnerabilityGroup(versions[0].PackageId, versions));
    }

    /// <summary>
    /// The CSV download (T7). All inputs are validated BEFORE any history
    /// read or filesystem access, so rejected input never touches the
    /// archive. A missing or unavailable history is an explicit 503 — never a
    /// fabricated empty report; a valid empty interval is a header-only CSV.
    /// The download inherits the page's read policy (NuGet basic auth).
    /// </summary>
    public async Task<IActionResult> OnGetExportCsvAsync(
        string from,
        string to,
        string packageId,
        string version,
        CancellationToken cancellationToken)
    {
        // 1. Input validation first; nothing below runs for rejected input.
        var validationError = ValidateExportInputs(
            from, to, packageId, version,
            out var fromDate, out var toDate, out var packageIdFilter, out var versionFilter);
        if (validationError != null)
        {
            return PlainText(400, validationError);
        }

        // 2. The history archive must exist and be readable; the live
        // analysis above is never touched by this handler.
        if (_historyStore == null || !_historyStore.IsConfigured)
        {
            return PlainText(
                503,
                "Vulnerability history is not configured (Vulnerabilities:History:Path), " +
                "so no analysis history CSV can be exported.");
        }

        var status = _historyStore.GetStatus();
        if (status.Availability == VulnerabilityHistoryAvailability.Unavailable)
        {
            return PlainText(
                503,
                "The vulnerability analysis history is currently unavailable, " +
                "so the CSV export was aborted. " +
                (status.LastError ?? "The configured history path is not usable."));
        }

        if (_csvExporter == null)
        {
            return PlainText(
                503,
                "Vulnerability history is not configured (Vulnerabilities:History:Path), " +
                "so no analysis history CSV can be exported.");
        }

        // 3. Build the complete export BEFORE any response header is sent, so
        // a corrupt or unreadable history fails the whole download instead of
        // delivering a partial CSV.
        try
        {
            var export = await _csvExporter.ExportAsync(
                fromDate, toDate, packageIdFilter, versionFilter, cancellationToken);
            return new FileStreamResult(export.Content, VulnerabilityCsvExporter.ContentType)
            {
                FileDownloadName = export.FileName,
            };
        }
        catch (VulnerabilityHistoryUnavailableException exception)
        {
            return PlainText(
                503,
                "The vulnerability analysis history could not be read, so the CSV export " +
                "was aborted instead of returning a partial download. " + exception.Message);
        }
    }

    private static string ValidateExportInputs(
        string from,
        string to,
        string packageId,
        string version,
        out DateOnly fromDate,
        out DateOnly toDate,
        out string packageIdFilter,
        out string versionFilter)
    {
        fromDate = default;
        toDate = default;
        packageIdFilter = null;
        versionFilter = null;

        if (string.IsNullOrWhiteSpace(from))
        {
            return "The export request is invalid: the 'from' date is required and " +
                   "must use the exact YYYY-MM-DD format (UTC).";
        }

        if (string.IsNullOrWhiteSpace(to))
        {
            return "The export request is invalid: the 'to' date is required and " +
                   "must use the exact YYYY-MM-DD format (UTC).";
        }

        if (!DateOnly.TryParseExact(
                from.Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out fromDate))
        {
            return "The export request is invalid: the 'from' date must use the exact " +
                   "YYYY-MM-DD format (UTC), not '" + from + "'.";
        }

        if (!DateOnly.TryParseExact(
                to.Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out toDate))
        {
            return "The export request is invalid: the 'to' date must use the exact " +
                   "YYYY-MM-DD format (UTC), not '" + to + "'.";
        }

        if (fromDate > toDate)
        {
            return "The export request is invalid: the 'from' date must not be after the 'to' date.";
        }

        if (!string.IsNullOrWhiteSpace(packageId))
        {
            packageIdFilter = packageId.Trim();
        }

        if (!string.IsNullOrWhiteSpace(version))
        {
            if (!NuGetVersion.TryParse(version.Trim(), out _))
            {
                return "The export request is invalid: the 'version' filter must be a valid " +
                       "NuGet version (for example 1.2.3), not '" + version + "'.";
            }

            versionFilter = version.Trim();
        }

        return null;
    }

    private static ContentResult PlainText(int statusCode, string message)
    {
        return new ContentResult
        {
            Content = message,
            ContentType = "text/plain",
            StatusCode = statusCode,
        };
    }

    /// <summary>
    /// Runs the real scan (<see cref="HostedVulnerabilityService.RefreshAsync"/>)
    /// and redirects back to the dashboard. Razor Pages validates the antiforgery
    /// token for non-GET requests automatically.
    /// </summary>
    public async Task<IActionResult> OnPostRefreshAsync(CancellationToken cancellationToken)
    {
        await _scanner.RefreshAsync(cancellationToken);
        return RedirectToPage();
    }

    public string DisplayStatus
    {
        get
        {
            switch (EffectiveStatus)
            {
                case HostedVulnerabilityStatus.NotScanned: return "Not scanned";
                case HostedVulnerabilityStatus.Scanning: return "Scanning";
                case HostedVulnerabilityStatus.Complete: return "Complete";
                case HostedVulnerabilityStatus.Failed: return "Failed";
                default: return EffectiveStatus.ToString();
            }
        }
    }

    public string LastSuccessfulScanText =>
        Snapshot.ScanTimeUtc?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'");

    // Counts: package counts (hosted ID + version rows), advisory associations
    // (findings), and unique advisory links are deliberately distinct values.

    /// <summary>Total hosted package rows (ID + version) covered by the snapshot.</summary>
    public int PackageRowCount => Snapshot.Packages.Count;

    public int PackagesWithFindingsCount => Snapshot.PackagesWithFindings;

    /// <summary>Advisory associations: one finding = one advisory matching one package (row or dependency).</summary>
    public int FindingCount => Snapshot.Packages.Sum(package => package.Findings.Count);

    public int ConfirmedFindingCount => Findings.Count(finding => finding.IsConfirmed);

    public int PotentialFindingCount => FindingCount - ConfirmedFindingCount;

    /// <summary>Distinct advisory links referenced by the findings.</summary>
    public int UniqueAdvisoryCount => Findings
        .Select(finding => finding.AdvisoryUrl)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Count();

    public IReadOnlyList<HostedVulnerabilityFinding> Findings =>
        Snapshot.Packages.SelectMany(package => package.Findings).ToList();

    /// <summary>Findings (advisory associations) grouped and counted by severity name.</summary>
    public IReadOnlyList<SeverityCount> FindingsBySeverity => Findings
        .GroupBy(finding => finding.SeverityName, StringComparer.Ordinal)
        .Select(group => new SeverityCount(group.Key, group.Count()))
        .OrderBy(count =>
        {
            switch (count.Name)
            {
                case "Critical": return 0;
                case "High": return 1;
                case "Moderate": return 2;
                case "Low": return 3;
                default: return 4;
            }
        })
        .ToList();

    /// <summary>The current one-based hosted-package page.</summary>
    public int PackagePageNumber { get; private set; } = 1;

    /// <summary>The number of distinct hosted package IDs in the full snapshot.</summary>
    public int TotalPackageGroupCount { get; private set; }

    /// <summary>The number of hosted-package pages (zero when there are no packages).</summary>
    public int TotalPackagePages { get; private set; }

    /// <summary>
    /// The first (one-based) package ID on the current page; packages, not
    /// version rows, are the pagination unit, and bounds use the effective
    /// (normalized) page size.
    /// </summary>
    public int FirstPackageNumber => TotalPackageGroupCount == 0
        ? 0
        : ((PackagePageNumber - 1) * EffectivePackagePageSize) + 1;

    public int LastPackageNumber => Math.Min(
        PackagePageNumber * EffectivePackagePageSize,
        TotalPackageGroupCount);

    public bool HasPreviousPackagePage => PackagePageNumber > 1;

    public bool HasNextPackagePage => PackagePageNumber < TotalPackagePages;

    /// <summary>Only this page's version rows, grouped by ID in scan ordering.</summary>
    public IReadOnlyList<PackageVulnerabilityGroup> PackageGroups { get; private set; } =
        Array.Empty<PackageVulnerabilityGroup>();

    public static string StateLabel(HostedPackageVulnerabilityState state)
    {
        switch (state)
        {
            case HostedPackageVulnerabilityState.Affected: return "Affected";
            case HostedPackageVulnerabilityState.PotentialExposure: return "Potential exposure";
            case HostedPackageVulnerabilityState.Incomplete: return "Incomplete";
            default: return "No known advisory";
        }
    }

    public static string StateBadgeClass(HostedPackageVulnerabilityState state)
    {
        switch (state)
        {
            case HostedPackageVulnerabilityState.Affected: return "label-danger";
            case HostedPackageVulnerabilityState.PotentialExposure: return "label-warning";
            case HostedPackageVulnerabilityState.Incomplete: return "label-warning";
            default: return "label-default";
        }
    }

    public static string SeverityBadgeClass(string severityName)
    {
        switch (severityName)
        {
            case "Critical": return "label-danger";
            case "High": return "label-warning";
            case "Moderate": return "label-info";
            case "Low": return "label-default";
            default: return "label-default";
        }
    }

    public sealed class SeverityCount
    {
        public SeverityCount(string name, int count)
        {
            Name = name;
            Count = count;
        }

        public string Name { get; }
        public int Count { get; }
    }

    public sealed class PackageVulnerabilityGroup
    {
        public PackageVulnerabilityGroup(
            string packageId,
            IReadOnlyList<HostedPackageVulnerability> versions)
        {
            PackageId = packageId;
            Versions = versions;
        }

        public string PackageId { get; }

        public IReadOnlyList<HostedPackageVulnerability> Versions { get; }

        /// <summary>The most severe state among the package's versions.</summary>
        public HostedPackageVulnerabilityState WorstState => Versions
            .Select(version => version.State)
            .OrderBy(SeverityPriority)
            .First();

        private static int SeverityPriority(HostedPackageVulnerabilityState state)
        {
            switch (state)
            {
                case HostedPackageVulnerabilityState.Affected: return 0;
                case HostedPackageVulnerabilityState.Incomplete: return 1;
                case HostedPackageVulnerabilityState.PotentialExposure: return 2;
                default: return 3;
            }
        }
    }
}
