using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BaGetter.Authentication;
using BaGetter.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BaGetter.Web;

/// <summary>
/// The global vulnerability dashboard. It shows the real, current snapshot
/// produced by <see cref="HostedVulnerabilityService"/> and lets operators
/// trigger an explicit rescan. A regular GET only reads the last snapshot —
/// it never starts a scan; scans run automatically in the background (hourly)
/// or when the Rescan form is submitted (with antiforgery protection).
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.NugetBasicAuthenticationScheme, Policy = AuthenticationConstants.NugetUserPolicy)]
public class VulnerabilitiesModel : PageModel
{
    private readonly HostedVulnerabilityService _scanner;

    public VulnerabilitiesModel(HostedVulnerabilityService scanner)
    {
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
    }

    /// <summary>The latest stable snapshot (never null).</summary>
    public HostedVulnerabilitySnapshot Snapshot { get; private set; }

    /// <summary>
    /// The lifecycle state including the transient "Scanning" state while a
    /// refresh is running.
    /// </summary>
    public HostedVulnerabilityStatus EffectiveStatus { get; private set; }

    public void OnGet()
    {
        Snapshot = _scanner.Current;
        EffectiveStatus = _scanner.Status;
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

    /// <summary>
    /// The snapshot rows grouped by hosted package ID (case-insensitive),
    /// keeping the scanner's ordering (affected rows first).
    /// </summary>
    public IReadOnlyList<PackageVulnerabilityGroup> PackageGroups => Snapshot.Packages
        .GroupBy(package => package.PackageId, StringComparer.OrdinalIgnoreCase)
        .Select(group => new PackageVulnerabilityGroup(group.Key, group.ToList()))
        .ToList();

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