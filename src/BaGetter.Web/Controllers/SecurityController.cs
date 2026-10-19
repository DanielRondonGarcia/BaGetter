using System;
using System.Linq;
using BaGetter.Authentication;
using BaGetter.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BaGetter.Web.Controllers;

/// <summary>
/// A read-only JSON view of the current hosted vulnerability snapshot
/// (<see cref="HostedVulnerabilityService.Current"/>). The snapshot is produced
/// automatically by the periodic background scan (hourly), or on demand through
/// the dashboard's Rescan form. There is no report import endpoint: arbitrary
/// vulnerability reports cannot be loaded into the server.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = AuthenticationConstants.NugetBasicAuthenticationScheme, Policy = AuthenticationConstants.NugetUserPolicy)]
public class SecurityController : ControllerBase
{
    private readonly HostedVulnerabilityService _scanner;

    public SecurityController(HostedVulnerabilityService scanner)
    {
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
    }

    [HttpGet]
    public IActionResult Get()
    {
        var snapshot = _scanner.Current;
        return Ok(ToPayload(snapshot));
    }

    private static object ToPayload(BaGetter.Web.Services.HostedVulnerabilitySnapshot snapshot)
    {
        var findings = snapshot.Packages
            .SelectMany(package => package.Findings)
            .ToList();

        return new
        {
            status = snapshot.Status.ToString(),
            scanTimeUtc = snapshot.ScanTimeUtc,
            startedUtc = snapshot.StartedUtc,
            isStale = snapshot.IsStale,
            error = snapshot.Error,
            packageRowCount = snapshot.Packages.Count,
            packagesWithFindings = snapshot.PackagesWithFindings,
            findingCount = findings.Count,
            confirmedFindingCount = findings.Count(finding => finding.IsConfirmed),
            potentialFindingCount = findings.Count(finding => !finding.IsConfirmed),
            uniqueAdvisoryCount = findings
                .Select(finding => finding.AdvisoryUrl)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            packages = snapshot.Packages.Select(package => new
            {
                packageId = package.PackageId,
                packageVersion = package.PackageVersion,
                state = package.State.ToString(),
                note = package.Note,
                findings = package.Findings.Select(finding => new
                {
                    packageId = finding.PackageId,
                    packageVersion = finding.PackageVersion,
                    dependencyId = finding.DependencyId,
                    dependencyRange = finding.DependencyRange,
                    targetFramework = finding.TargetFramework,
                    advisoryUrl = finding.AdvisoryUrl,
                    severity = finding.Severity,
                    severityName = finding.SeverityName,
                    affectedRange = finding.AffectedRange,
                    isConfirmed = finding.IsConfirmed
                })
            })
        };
    }
}