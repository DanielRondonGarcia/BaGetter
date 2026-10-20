using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using BaGetter.Web.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Abstractions;

namespace BaGetter.Tests;

/// <summary>
/// Public HTTP integration tests for the hosted vulnerability dashboard
/// (/vulnerabilities page, /api/security snapshot, and the per-package
/// accordion) connected to the real HostedVulnerabilityService in T1.
///
/// The official NuGet vulnerability feed is replaced by fake HTTP responses;
/// no test ever contacts live nuget.org.
/// </summary>
public class SecurityDashboardIntegrationTests
{
    private const string VulnerabilityIndexUrl = "https://feed.test/v3/vulnerabilities/index.json";
    private const string BasePageUrl = "https://feed.test/v3-vulnerabilities/vulnerability.base.json";
    private const string ServiceIndexUrl = NuGetVulnerabilityFeed.ServiceIndexUrl;
    private const string AdvisoryUrl = "https://github.com/advisories/GHSA-test-vuln-0001";

    private const string VulnerabilityIndexJson =
        "[{\"@name\":\"base\",\"@id\":\"" + BasePageUrl +
        "\",\"@updated\":\"2023-06-01T06:14:58.4159909Z\"}]";

    private static string ServiceIndexJson =>
        "{\"version\":\"3.0.0\",\"resources\":[" +
        "{\"@id\":\"" + VulnerabilityIndexUrl + "\",\"@type\":\"VulnerabilityInfo/6.7.0\"}]}";

    private static string FeedPage(string packageId, string versions, int severity = 3)
    {
        return "{\"" + packageId.ToLowerInvariant() + "\":[{" +
               "\"url\":\"" + AdvisoryUrl + "\"," +
               "\"severity\":" + severity + ",\"versions\":\"" + versions + "\"}]}";
    }

    private static string EmptyFeedPage() => "[]";

    private readonly ITestOutputHelper _output;

    public SecurityDashboardIntegrationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    private static FakeFeedHttpHandler SuccessfulFeedHandler(string packageId = "testdata")
    {
        var handler = new FakeFeedHttpHandler();
        handler.SetResponse(ServiceIndexUrl, ServiceIndexJson);
        handler.SetResponse(VulnerabilityIndexUrl, VulnerabilityIndexJson);
        handler.SetResponse(BasePageUrl, FeedPage(packageId, "[1.2.3, 2.0.0)"));
        return handler;
    }

    private static FakeFeedHttpHandler FailingFeedHandler()
    {
        // No configured responses: every feed request fails with 404.
        return new FakeFeedHttpHandler();
    }

    private static SecurityDashboardApplication CreateSuccessfulApp(
        ITestOutputHelper output,
        FakeFeedHttpHandler handler = null)
    {
        handler ??= SuccessfulFeedHandler();
        return new SecurityDashboardApplication(output, handler, configureCredentials: false);
    }

    // T1: the pagination unit is the case-insensitive package ID, and the
    // initial render shows only summary headers. Version and finding content
    // loads lazily from the PackageDetails fragment when a group is expanded.
    [Fact]
    public async Task GetVulnerabilities_PaginatesByPackageId_InitialPageShowsSummaryOnly()
    {
        var handler = SuccessfulFeedHandler();
        handler.SetResponse(BasePageUrl, FeedPage("Pagination.ManyVersions", "[1.0.0, 2.0.0)", severity: 2));
        using var app = CreateSuccessfulApp(_output, handler);
        for (var index = 0; index < 120; index++)
        {
            await app.AddPackageAsync(PackageStreamBuilder.Build("Pagination.ManyVersions", "1.0." + index));
        }
        await app.RunScanAsync();
        var requestsAfterScan = app.Feed.RequestCount;
        var snapshotBefore = await app.GetStringAsync("api/security");
        using var snapshot = JsonDocument.Parse(snapshotBefore);
        var expectedVersions = snapshot.RootElement.GetProperty("packages").EnumerateArray()
            .Select(package => package.GetProperty("packageVersion").GetString()).ToArray();
        Assert.Equal(120, snapshot.RootElement.GetProperty("packageRowCount").GetInt32());
        Assert.Equal(120, snapshot.RootElement.GetProperty("findingCount").GetInt32());

        using var response = await app.GetAsync("vulnerabilities");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();

        // One package group = one pagination unit, however many versions it holds.
        Assert.Equal(1, Regex.Matches(content, "<strong>Pagination[.]ManyVersions</strong>").Count);
        Assert.Contains("120 versions, loaded when expanded", content);
        // A package is never paginated away by its own version count.
        Assert.DoesNotContain("page 2", content);
        Assert.DoesNotContain("pageNumber=2", content);
        // Raising the size never reintroduces version-row or eager-detail behavior.
        using var sized = await app.GetAsync("vulnerabilities?pageSize=5000");
        Assert.Equal(HttpStatusCode.OK, sized.StatusCode);
        var sizedContent = await sized.Content.ReadAsStringAsync();
        Assert.Contains("page 1 of 1", sizedContent);
        Assert.Equal(1, Regex.Matches(sizedContent, "<strong>Pagination[.]ManyVersions</strong>").Count);
        Assert.DoesNotContain("class=\"vulnerability-version\"", sizedContent);
        // Deliberately lazy: the initial payload must not embed detail markup
        // (not even hidden) and must not expose advisory content directly.
        Assert.DoesNotContain("class=\"vulnerability-version\"", content);
        Assert.DoesNotContain(AdvisoryUrl, content);
        // The lazy-loading client hooks must be present on the summary group;
        // the script is deferred and cache-busted via the existing asset prefix.
        Assert.Contains("data-package-id=\"Pagination.ManyVersions\"", content);
        Assert.Contains("data-package-details", content);
        var scriptMatch = Regex.Match(content, "<script[^>]*vulnerabilities[^>]*>");
        Assert.True(
            scriptMatch.Success,
            "rendered vulnerabilities script: " + (scriptMatch.Success ? scriptMatch.Value : "MISSING; all script tags: " +
                string.Join("|", Regex.Matches(content, "<script[^>]*>").Select(m => m.Value))));
        // Deferred, cache-busted client script through the existing asset prefix.
        Assert.Matches(
            "<script[^>]*src=\"[^\"]*_content/BaGetter[.]Web/js/vulnerabilities[.]js[^\"]*\"[^>]*defer[^>]*>",
            scriptMatch.Success ? scriptMatch.Value : "");
        // NOTE: in the test host the asp-append-version provider resolves the
        // _content manifest path without emitting a ?v= query; browser-level
        // cache-busting proof stays with the parent's T3 browser checks.
        // Aggregate counts still describe the full snapshot, not just headers.
        Assert.Contains("<h4>120</h4>", content);
        Assert.Contains("120 findings", content);

        // The fragment must contain every version, in snapshot order.
        using var details = await app.GetAsync("vulnerabilities?handler=PackageDetails&packageId=Pagination.ManyVersions");
        Assert.Equal(HttpStatusCode.OK, details.StatusCode);
        Assert.Equal("no-store", details.Headers.GetValues("Cache-Control").Single());
        var detailsContent = await details.Content.ReadAsStringAsync();
        Assert.DoesNotContain(AdvisoryUrl, content); // main page stays summary-only
        Assert.Contains(AdvisoryUrl, detailsContent);
        Assert.Equal(120, Regex.Matches(detailsContent, "class=\"vulnerability-version\"").Count);
        var shownVersions = Regex.Matches(detailsContent,
                @"<div class=""vulnerability-version"">\s*<p>\s*<a[^>]*>\s*Pagination[.]ManyVersions (1[.]0[.]\d+)\s*</a>")
            .Select(match => match.Groups[1].Value).ToArray();
        Assert.Equal(expectedVersions, shownVersions);

        Assert.Equal(snapshotBefore, await app.GetStringAsync("api/security"));
        Assert.Equal(requestsAfterScan, app.Feed.RequestCount);
    }

    [Fact]
    public async Task GetVulnerabilities_PackageDetailsFragment_ReturnsEscapedEvidence()
    {
        var handler = new FakeFeedHttpHandler();
        handler.SetResponse(ServiceIndexUrl, ServiceIndexJson);
        handler.SetResponse(VulnerabilityIndexUrl, VulnerabilityIndexJson);
        // The declared dependency ID is rendered by the fragment; the nuspec
        // stores it with standard XML entity escapes, so it decodes to "Evil&Dep".
        handler.SetResponse(BasePageUrl, FeedPage("evil&dep", "[1.0.0, 2.0.0)", severity: 2));

        using var app = new SecurityDashboardApplication(_output, handler, configureCredentials: false);
        await app.AddPackageAsync(PackageStreamBuilder.Build(
            "Private.Escaping", "9.9.9",
            new PackageStreamBuilder.Dependency("Evil&amp;Dep", "[1.0.0]", "net9.0")));
        await app.RunScanAsync();

        using var response = await app.GetAsync(
            "vulnerabilities?handler=PackageDetails&packageId=private.escaping"); // lowercase: case-insensitive match
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();

        Assert.Contains(AdvisoryUrl, content);
        Assert.Contains("[1.0.0, 2.0.0)", content); // feed-published affected range, verbatim
        // Razor escaping: '&' must render as &amp;, never as raw markup.
        Assert.Contains("Evil&amp;Dep", content);
        Assert.DoesNotContain("Evil&Dep", content);
    }

    [Fact]
    public async Task GetVulnerabilities_PackageDetailsFragment_RejectsBadIdsWithoutSideEffects()
    {
        using var app = CreateSuccessfulApp(_output, SuccessfulFeedHandler("testdata"));
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();
        var requestsAfterScan = app.Feed.RequestCount;
        var snapshotBefore = await app.GetStringAsync("api/security");

        // A missing or empty ID is a 400, never a full-page render.
        using var missing = await app.GetAsync("vulnerabilities?handler=PackageDetails");
        using var empty = await app.GetAsync("vulnerabilities?handler=PackageDetails&packageId=");
        using var blank = await app.GetAsync("vulnerabilities?handler=PackageDetails&packageId=%20");
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, empty.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, blank.StatusCode);

        // An unknown ID is an explicit 404, never a fabricated empty group.
        using var unknown = await app.GetAsync(
            "vulnerabilities?handler=PackageDetails&packageId=Not.Hosted");
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.True((await unknown.Content.ReadAsStringAsync()).Length > 0);

        // The details handler is size-independent: pageSize is ignored there.
        using var sized = await app.GetAsync(
            "vulnerabilities?handler=PackageDetails&packageId=TestData&pageSize=5000");
        Assert.Equal(HttpStatusCode.OK, sized.StatusCode);
        Assert.Contains("class=\"vulnerability-version\"", await sized.Content.ReadAsStringAsync());

        // Rejected fragments must never mutate the analysis or contact the feed.
        Assert.Equal(snapshotBefore, await app.GetStringAsync("api/security"));
        Assert.Equal(requestsAfterScan, app.Feed.RequestCount);
    }

    [Fact]
    public async Task GetVulnerabilities_PaginationLinks_RoundTripAndPreserveExportFilters()
    {
        using var app = CreateSuccessfulApp(_output);
        await AddPaginationPackagesAsync(app);
        var requestsAfterScan = app.Feed.RequestCount;
        var snapshotBefore = await app.GetStringAsync("api/security");

        using var firstResponse = await app.GetAsync(
            "vulnerabilities?exportPackageId=Private.App&exportVersion=1.0.0");
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        var first = await firstResponse.Content.ReadAsStringAsync();
        Assert.Equal(Enumerable.Range(1, 50).Select(PaginationPackageId), DisplayedPaginationPackages(first));
        Assert.Contains("page 1 of 2", first);
        // Lazy behavior: the package list carries no per-version detail markup.
        Assert.DoesNotContain("class=\"vulnerability-version\"", first);
        Assert.DoesNotContain(AdvisoryUrl, first);

        var next = PaginationLink(first, "next");
        Assert.Contains("pageNumber=2", next);
        Assert.Contains("exportPackageId=Private.App", next);
        Assert.Contains("exportVersion=1.0.0", next);
        using var secondResponse = await app.GetAsync(next);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        var second = await secondResponse.Content.ReadAsStringAsync();
        Assert.Equal(Enumerable.Range(51, 5).Select(PaginationPackageId), DisplayedPaginationPackages(second));
        Assert.Contains("page 2 of 2", second);
        Assert.Contains("<h4>55</h4>", second);

        var previous = PaginationLink(second, "previous");
        Assert.Contains("pageNumber=1", previous);
        Assert.Contains("exportPackageId=Private.App", previous);
        Assert.Contains("exportVersion=1.0.0", previous);
        using var backResponse = await app.GetAsync(previous);
        Assert.Equal(HttpStatusCode.OK, backResponse.StatusCode);
        var back = await backResponse.Content.ReadAsStringAsync();
        Assert.Equal(DisplayedPaginationPackages(first), DisplayedPaginationPackages(back));
        Assert.Contains("page 1 of 2", back);
        Assert.Equal(snapshotBefore, await app.GetStringAsync("api/security"));
        Assert.Equal(requestsAfterScan, app.Feed.RequestCount);
    }

    [Theory]
    [InlineData(99, 2, 51, 5)]
    [InlineData(0, 1, 1, 50)]
    [InlineData(-3, 1, 1, 50)]
    public async Task GetVulnerabilities_PaginationQuery_ClampsThroughHttp(
        int requestedPage, int expectedPage, int firstPackage, int count)
    {
        using var app = CreateSuccessfulApp(_output);
        await AddPaginationPackagesAsync(app);
        var requestsAfterScan = app.Feed.RequestCount;
        var snapshotBefore = await app.GetStringAsync("api/security");

        using var response = await app.GetAsync("vulnerabilities?pageNumber=" + requestedPage);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("page " + expectedPage + " of 2", content);
        Assert.Equal(
            Enumerable.Range(firstPackage, count).Select(PaginationPackageId),
            DisplayedPaginationPackages(content));
        Assert.Contains("<h4>55</h4>", content);
        Assert.Equal(snapshotBefore, await app.GetStringAsync("api/security"));
        Assert.Equal(requestsAfterScan, app.Feed.RequestCount);
    }

    // T2/S3: the optional pageSize query normalizes the package-group page
    // size: default 50, positive values are honored up to a 1000 cap,
    // nonpositive values fall back to 50. The requested size is honored
    // truthfully in the selector (never "50" while serving 75), and the page
    // number clamps against the chosen size's available pages.
    [Theory]
    [InlineData(100, 100, 1, 55)]
    [InlineData(1000, 1000, 1, 55)]
    [InlineData(5000, 1000, 1, 55)]
    [InlineData(0, 50, 2, 50)]
    [InlineData(-3, 50, 2, 50)]
    [InlineData(75, 75, 1, 55)]
    public async Task GetVulnerabilities_PageSizeQuery_IsNormalizedThroughHttp(
        int requestedSize, int effectiveSize, int expectedPages, int shownGroups)
    {
        using var app = CreateSuccessfulApp(_output);
        await AddPaginationPackagesAsync(app);
        var requestsAfterScan = app.Feed.RequestCount;
        var snapshotBefore = await app.GetStringAsync("api/security");

        using var response = await app.GetAsync("vulnerabilities?pageSize=" + requestedSize);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("page 1 of " + expectedPages, content);
        Assert.Equal(
            Enumerable.Range(1, shownGroups).Select(PaginationPackageId),
            DisplayedPaginationPackages(content));
        // The selector shows the size that is actually serving, never a preset lie.
        Assert.Equal(
            new[] { effectiveSize.ToString() },
            SelectedPageSizeOptions(content));
        // Aggregate counts and lazy behavior are size-independent.
        Assert.Contains("<h4>55</h4>", content);
        Assert.DoesNotContain("class=\"vulnerability-version\"", content);
        Assert.DoesNotContain(AdvisoryUrl, content);
        Assert.Equal(snapshotBefore, await app.GetStringAsync("api/security"));
        Assert.Equal(requestsAfterScan, app.Feed.RequestCount);
    }

    // A positive nonpreset size (75) must be reflected truthfully as a
    // transient selected option; presets stay unselected then.
    [Fact]
    public async Task GetVulnerabilities_PageSizeSelector_ReflectsNonPresetSizeTruthfully()
    {
        using var app = CreateSuccessfulApp(_output);
        await AddPaginationPackagesAsync(app);

        using var response = await app.GetAsync("vulnerabilities?pageSize=75");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();

        Assert.Contains("<option value=\"75\" selected=\"selected\">75</option>", content);
        Assert.DoesNotContain("<option value=\"50\" selected", content);
        // The preset options still exist.
        foreach (var preset in new[] { 50, 100, 250, 500, 1000 })
        {
            Assert.Contains(">" + preset + "</option>", content);
        }
    }

    // The Apply form is a plain GET form: it carries the effective size and
    // existing export prefills as successful controls (browser GET forms
    // replace the action's query), and never a pageNumber control — so
    // changing the size resets to page 1.
    [Fact]
    public async Task GetVulnerabilities_PageSizeForm_CarriesPrefillsAndResetsToFirstPage()
    {
        using var app = CreateSuccessfulApp(_output);
        await AddPaginationPackagesAsync(app);

        using var response = await app.GetAsync(
            "vulnerabilities?exportPackageId=Private.App&exportVersion=1.0.0&pageSize=75");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        var form = PageSizedForm(content);

        Assert.Contains("method=\"get\"", form);
        Assert.Contains("\"vulnerability-page-size\"", form);
        Assert.Contains("Apply", form);
        Assert.Contains("name=\"exportPackageId\" value=\"Private.App\"", form);
        Assert.Contains("name=\"exportVersion\" value=\"1.0.0\"", form);
        // Changing the size resets to page 1: no pageNumber in the successful controls.
        Assert.DoesNotContain("name=\"pageNumber\"", form);
        Assert.DoesNotContain("name=\"handler\"", form);
    }

    [Fact]
    public async Task GetVulnerabilities_PageSizeLinks_PreserveNormalizedSizeAndPrefills()
    {
        using var app = CreateSuccessfulApp(_output);
        await AddPaginationPackagesAsync(app);

        var url = "vulnerabilities?pageSize=25&exportPackageId=Private.App&exportVersion=1.0.0";
        using var firstResponse = await app.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        var first = await firstResponse.Content.ReadAsStringAsync();
        Assert.Contains("page 1 of 3", first);
        Assert.Equal(Enumerable.Range(1, 25).Select(PaginationPackageId), DisplayedPaginationPackages(first));
        Assert.Equal(new[] { "25" }, SelectedPageSizeOptions(first));

        var next = PaginationLink(first, "next");
        Assert.Contains("pageNumber=2", next);
        Assert.Contains("pageSize=25", next);
        Assert.Contains("exportPackageId=Private.App", next);
        Assert.Contains("exportVersion=1.0.0", next);
        using var secondResponse = await app.GetAsync(next);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        var second = await secondResponse.Content.ReadAsStringAsync();
        Assert.Contains("page 2 of 3", second);
        Assert.Equal(Enumerable.Range(26, 25).Select(PaginationPackageId), DisplayedPaginationPackages(second));
        Assert.Equal(new[] { "25" }, SelectedPageSizeOptions(second));

        // Overshooting clamps against the chosen size's pages: page 3 of 3.
        using var last = await app.GetAsync("vulnerabilities?pageNumber=99&pageSize=25");
        Assert.Equal(HttpStatusCode.OK, last.StatusCode);
        var lastContent = await last.Content.ReadAsStringAsync();
        Assert.Contains("page 3 of 3", lastContent);
        Assert.Equal(Enumerable.Range(51, 5).Select(PaginationPackageId), DisplayedPaginationPackages(lastContent));

        var previous = PaginationLink(second, "previous");
        Assert.Contains("pageNumber=1", previous);
        Assert.Contains("pageSize=25", previous);
    }

    private static string PageSizedForm(string content)
    {
        var match = Regex.Match(
            content,
            "<form[^>]*vulnerability-page-size-form[^>]*>[\\s\\S]*?</form>");
        Assert.True(match.Success, "the page-size Apply form must be rendered.");
        return match.Value;
    }

    private static string[] SelectedPageSizeOptions(string content) => Regex
        .Matches(content, "<option value=\"([0-9]+)\" selected=\"selected\">")
        .Select(match => match.Groups[1].Value)
        .ToArray();

    private static string PaginationPackageId(int index) => "Pagination.Package." + index.ToString("D3");

    private static async Task AddPaginationPackagesAsync(SecurityDashboardApplication app)
    {
        for (var index = 1; index <= 55; index++)
        {
            await app.AddPackageAsync(PackageStreamBuilder.Build(PaginationPackageId(index), "1.0.0"));
        }

        await app.RunScanAsync();
    }

    private static string[] DisplayedPaginationPackages(string content) => Regex
        .Matches(content, "<strong>(Pagination[.]Package[.][0-9]+)</strong>")
        .Select(match => match.Groups[1].Value)
        .ToArray();

    private static string PaginationLink(string content, string direction)
    {
        var match = Regex.Match(content,
            "<li class=\"" + direction + "\">\\s*<a[^>]*href=\"([^\"]+)\"",
            RegexOptions.Singleline);
        Assert.True(match.Success, "Expected an enabled " + direction + " pagination link.");
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    [Fact]
    public async Task GetVulnerabilities_BeforeAnySuccessfulScan_ShowsExplicitStatusWithoutFindings()
    {
        using var app = new SecurityDashboardApplication(_output, FailingFeedHandler(), configureCredentials: false, disableScheduledScan: true);

        var content = await app.GetStringAsync("vulnerabilities");

        Assert.Contains("Vulnerabilities", content);
        Assert.Contains("No vulnerability scan has completed yet", content);
        // A GET must not invent data or claim cleanliness.
        Assert.DoesNotContain(AdvisoryUrl, content);
        // A regular GET must not launch the scan: no feed request was made.
        Assert.Equal(0, app.Feed.RequestCount);
    }

    [Fact]
    public async Task GetVulnerabilities_KnownVulnerableExactVersion_ShowsConfirmedFinding()
    {
        using var app = CreateSuccessfulApp(_output, SuccessfulFeedHandler("testdata"));
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();

        var content = await app.GetStringAsync("vulnerabilities");

        Assert.Contains("TestData", content); // hosted package id rendered
        Assert.Contains("Affected", content); // group worst state, summary level
        // Deliberately lazy: findings render in the fragment, not the initial page.
        Assert.DoesNotContain(AdvisoryUrl, content);
        Assert.DoesNotContain("class=\"vulnerability-findings-table\"", content);
        var fragment = await app.GetStringAsync(
            "vulnerabilities?handler=PackageDetails&packageId=TestData");
        Assert.Contains("Critical", fragment);
        Assert.Contains(AdvisoryUrl, fragment);
        Assert.Contains("Confirmed", fragment); // exact stored version match is confirmed
        // Counts must separate advisories (unique advisory links) from package counts.
        Assert.Contains("hosted package rows", content);
        Assert.Contains("unique advisories", content);
        // The page must never claim the absence of advisories is "safe".
        Assert.Contains("not covered", content);
    }

    [Fact]
    public async Task GetVulnerabilities_PrivatePackageWithVulnerableDeclaredRange_ShowsPotentialFinding()
    {
        var handler = new FakeFeedHttpHandler();
        handler.SetResponse(ServiceIndexUrl, ServiceIndexJson);
        handler.SetResponse(VulnerabilityIndexUrl, VulnerabilityIndexJson);
        handler.SetResponse(BasePageUrl, FeedPage("vulnerable.dep", "[1.0.0, 10.0.0)", severity: 2));

        using var app = new SecurityDashboardApplication(_output, handler, configureCredentials: false);
        await app.AddPackageAsync(PackageStreamBuilder.Build(
            "Private.App", "9.9.9",
            new PackageStreamBuilder.Dependency("Vulnerable.Dep", "[9.0.0, )", "net9.0")));
        await app.RunScanAsync();

        var content = await app.GetStringAsync("vulnerabilities");

        Assert.Contains("Private.App", content); // summary group header
        Assert.Contains("Potential exposure", content); // group worst state on the summary
        // Deliberately lazy: the finding evidence renders in the fragment only.
        Assert.DoesNotContain("[9.0.0, )", content);
        var fragment = await app.GetStringAsync(
            "vulnerabilities?handler=PackageDetails&packageId=Private.App");
        Assert.Contains("Vulnerable.Dep", fragment);
        Assert.Contains("[9.0.0, )", fragment); // declared (unpinned) range rendered
        Assert.Contains("[1.0.0, 10.0.0)", fragment); // advisory's affected range rendered
        Assert.Contains("High", fragment);
        Assert.Contains("Potential", fragment);
        Assert.DoesNotContain("Confirmed", fragment);
    }

    [Fact]
    public async Task GetVulnerabilities_FailedScan_ShowsExplicitErrorAndNeverClean()
    {
        using var app = new SecurityDashboardApplication(_output, FailingFeedHandler(), configureCredentials: false);
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();

        var content = await app.GetStringAsync("vulnerabilities");

        Assert.Contains("did not complete", content);
        // The state must be explicit, not a clean/zero-findings claim.
        Assert.DoesNotContain("No vulnerabilities found", content);
        Assert.True(app.Feed.RequestCount > 0, "the scan must have attempted the feed handler");
    }

    [Fact]
    public async Task GetVulnerabilities_StaleAfterFailedRefresh_ShowsPreservedResultsAndWarning()
    {
        var handler = SuccessfulFeedHandler("testdata");
        using var app = new SecurityDashboardApplication(_output, handler, configureCredentials: false);
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();
        var beforeRequests = handler.RequestCount;

        // The feed breaks; the preserved successful snapshot must stay visible, marked stale.
        handler.SetResponse(BasePageUrl, "{invalid");
        await app.RunScanAsync();

        var content = await app.GetStringAsync("vulnerabilities");

        Assert.Contains("stale", content, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("did not complete", content);
        // The preserved, stale results stay reachable through the fragment;
        // the initial page itself remains summary-only.
        Assert.DoesNotContain(AdvisoryUrl, content);
        var fragment = await app.GetStringAsync(
            "vulnerabilities?handler=PackageDetails&packageId=TestData");
        Assert.Contains(AdvisoryUrl, fragment);
        Assert.True(handler.RequestCount >= beforeRequests + 1, "the failed refresh must have attempted the feed");
    }

    [Fact]
    public async Task GetApiSecurity_ReturnsRealSnapshotCounts()
    {
        using var app = CreateSuccessfulApp(_output, SuccessfulFeedHandler("testdata"));
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();

        using var response = await app.GetAsync("api/security");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;

        Assert.Equal("Complete", root.GetProperty("status").GetString());
        Assert.False(root.GetProperty("isStale").GetBoolean());
        // One hosted package row (ID + version), distinct from finding counts.
        Assert.Equal(1, root.GetProperty("packageRowCount").GetInt32());
        Assert.Equal(1, root.GetProperty("findingCount").GetInt32());
        Assert.Equal(1, root.GetProperty("confirmedFindingCount").GetInt32());
        Assert.Equal(0, root.GetProperty("potentialFindingCount").GetInt32());
        // Unique advisory URLs differ from advisory associations.
        Assert.Equal(1, root.GetProperty("uniqueAdvisoryCount").GetInt32());

        var packages = root.GetProperty("packages");
        Assert.Equal(1, packages.GetArrayLength());
        var package = packages[0];
        Assert.Equal("TestData", package.GetProperty("packageId").GetString());
        Assert.Equal("Affected", package.GetProperty("state").GetString());
        var findings = package.GetProperty("findings");
        Assert.Equal(1, findings.GetArrayLength());
        var finding = findings[0];
        Assert.Equal(AdvisoryUrl, finding.GetProperty("advisoryUrl").GetString());
        Assert.Equal("Critical", finding.GetProperty("severityName").GetString());
        Assert.True(finding.GetProperty("isConfirmed").GetBoolean());
        Assert.Equal("[1.2.3, 2.0.0)", finding.GetProperty("affectedRange").GetString());
        Assert.Equal("TestData", finding.GetProperty("dependencyId").GetString());
    }

    [Fact]
    public async Task GetApiSecurity_BeforeAnySuccessfulScan_ReportsNotScanned()
    {
        using var app = new SecurityDashboardApplication(_output, FailingFeedHandler(), configureCredentials: false, disableScheduledScan: true);

        using var response = await app.GetAsync("api/security");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("NotScanned", document.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task GetPackagePage_ShowsVulnerabilitiesAccordionWithFinding()
    {
        using var app = CreateSuccessfulApp(_output, SuccessfulFeedHandler("testdata"));
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();

        var content = await app.GetStringAsync("packages/TestData");

        Assert.Contains("Vulnerabilities", content);
        Assert.Contains(AdvisoryUrl, content);
        Assert.Contains("Confirmed", content);
        // Existing sections are preserved (shared page, model and layout).
        Assert.Contains("Dependencies", content);
        Assert.Contains("Versions", content);
        Assert.Contains("Used By", content);
    }

    [Fact]
    public async Task GetPackagePage_CaseInsensitiveIdAndVersionMatch_ShowsFinding()
    {
        using var app = CreateSuccessfulApp(_output, SuccessfulFeedHandler("testdata"));
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();

        var upper = await app.GetStringAsync("packages/TESTDATA/1.2.3");

        Assert.Contains(AdvisoryUrl, upper);
        Assert.Contains("Confirmed", upper);
    }

    [Fact]
    public async Task GetPackagePage_NoKnownAdvisory_ShowsExplicitNotCoveredMessage()
    {
        var handler = new FakeFeedHttpHandler();
        handler.SetResponse(ServiceIndexUrl, ServiceIndexJson);
        handler.SetResponse(VulnerabilityIndexUrl, VulnerabilityIndexJson);
        handler.SetResponse(BasePageUrl, EmptyFeedPage());

        using var app = new SecurityDashboardApplication(_output, handler, configureCredentials: false);
        await app.AddPackageAsync(PackageStreamBuilder.Build("Private.Clean", "2.0.0"));
        await app.RunScanAsync();

        var content = await app.GetStringAsync("packages/Private.Clean");

        Assert.Contains("No known advisory", content);
        // Absence of advisories must never be presented as "safe".
        Assert.Contains("not", content);
    }

    [Fact]
    public async Task GetPackagePage_HostedAfterLastScan_ShowsExplicitNotScanned()
    {
        using var app = CreateSuccessfulApp(_output, SuccessfulFeedHandler("testdata"));
        await app.RunScanAsync(); // scan before this package existed

        await app.AddPackageAsync(PackageStreamBuilder.Build("Later.Package", "1.0.0"));

        var content = await app.GetStringAsync("packages/Later.Package");

        Assert.Contains("not been scanned yet", content);
        // Must not be presented as clean.
        Assert.DoesNotContain("safe", content, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetPackagePage_FailedScanWithNoResults_ShowsExplicitMessage()
    {
        using var app = new SecurityDashboardApplication(_output, FailingFeedHandler(), configureCredentials: false);
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();

        var content = await app.GetStringAsync("packages/TestData");

        Assert.Contains("did not complete", content);
    }

    [Fact]
    public async Task GetVulnerabilities_DoesNotTriggerFeedRequest()
    {
        using var app = CreateSuccessfulApp(_output, SuccessfulFeedHandler("testdata"));
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();
        var requestsAfterScan = app.Feed.RequestCount;
        Assert.True(requestsAfterScan > 0, "the explicit scan must have contacted the feed");

        await app.GetStringAsync("vulnerabilities");
        await app.GetStringAsync("packages/TestData");
        await app.GetAsync("api/security");
        await app.GetAsync("vulnerabilities?handler=PackageDetails&packageId=TestData");
        await app.GetAsync("vulnerabilities?handler=PackageDetails&packageId=Not.Hosted");
        await app.GetAsync("vulnerabilities?handler=PackageDetails&packageId=");

        // A regular GET must not launch a network request; only the
        // background service and the explicit Rescan POST refresh.
        Assert.Equal(requestsAfterScan, app.Feed.RequestCount);
    }

    [Fact]
    public async Task PostRescan_WithAntiforgery_TriggersRealRefreshAndRedirects()
    {
        using var app = CreateSuccessfulApp(_output, SuccessfulFeedHandler("testdata"));

        // The first scan (via the background scan at startup) sees the broken
        // feed; the operator then fixes the feed and rescans from the UI.
        await app.AddPackageAsync(TestResources.GetResourceStream(TestResources.Package));
        await app.RunScanAsync();

        var (token, cookie) = await app.GetAntiforgeryTokenAsync("vulnerabilities");
        var requestsBeforeRescan = app.Feed.RequestCount;

        // The feed is fixed; the Rescan form must trigger the real RefreshAsync
        // so the fresh successful scan replaces the failure (never confusing
        // stale previous results with the current state).
        app.Feed.SetResponse(ServiceIndexUrl, ServiceIndexJson);
        app.Feed.SetResponse(VulnerabilityIndexUrl, VulnerabilityIndexJson);
        app.Feed.SetResponse(BasePageUrl, FeedPage("testdata", "[1.2.3, 2.0.0)"));

        var redirect = app.SendPostToVulnerabilities(token, cookie);
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        var redirectPath = redirect.Headers.Location?.IsAbsoluteUri == true
            ? redirect.Headers.Location.PathAndQuery
            : redirect.Headers.Location?.OriginalString;
        Assert.Equal("/vulnerabilities", redirectPath);

        using var response = await app.GetAsync("api/security");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Complete", document.RootElement.GetProperty("status").GetString());
        Assert.False(document.RootElement.GetProperty("isStale").GetBoolean());
        Assert.Equal(1, document.RootElement.GetProperty("findingCount").GetInt32());
        Assert.True(
            app.Feed.RequestCount >= requestsBeforeRescan + 3,
            $"the rescan must have contacted the feed: before={requestsBeforeRescan} after={app.Feed.RequestCount}");
    }

    [Fact]
    public async Task SecurityPage_WithCredentialsConfigured_RejectsUnauthenticatedRequests()
    {
        var handler = SuccessfulFeedHandler("testdata");
        using var app = new SecurityDashboardApplication(_output, handler, configureCredentials: true);

        using var page = await app.GetAsync("vulnerabilities");
        using var api = await app.GetAsync("api/security");
        using var fragment = await app.GetAsync(
            "vulnerabilities?handler=PackageDetails&packageId=Any.Package");

        Assert.Equal(HttpStatusCode.Unauthorized, page.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, api.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, fragment.StatusCode);
        Assert.Equal("Basic realm=\"NuGet Server\"", api.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task SecurityPage_WithCredentialsConfigured_AllowsValidCredentials()
    {
        var handler = SuccessfulFeedHandler("testdata");
        using var app = new SecurityDashboardApplication(_output, handler, configureCredentials: true);
        app.Client.SetBasicCredentials("username", "password");

        using var page = await app.GetAsync("vulnerabilities");
        using var api = await app.GetAsync("api/security");
        using var fragment = await app.GetAsync(
            "vulnerabilities?handler=PackageDetails&packageId=Any.Package");

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Equal(HttpStatusCode.OK, api.StatusCode);
        // An unknown package ID still answers with an explicit 404 for
        // authenticated users — never an empty 200 and never a 401 fallback.
        Assert.Equal(HttpStatusCode.NotFound, fragment.StatusCode);
    }
}

/// <summary>
/// A fake HTTP response table standing in for the official NuGet
/// vulnerability feed. Every response is explicit; unset URLs fail with 404,
/// which the scanner must treat as a failed scan (never a clean report).
/// </summary>
public sealed class FakeFeedHttpHandler : HttpMessageHandler
{
    private readonly Dictionary<string, Func<HttpResponseMessage>> _responses =
        new Dictionary<string, Func<HttpResponseMessage>>(StringComparer.OrdinalIgnoreCase);

    private int _requests;

    public int RequestCount => _requests;

    public void SetResponse(string url, string json)
    {
        _responses[url] = () => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _requests);

        var url = request.RequestUri.GetLeftPart(UriPartial.Path);
        if (_responses.TryGetValue(url, out var responder))
        {
            return Task.FromResult(responder());
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}

/// <summary>
/// SecurityDashboardApplication boots BaGetter exactly like the real host
/// (Startup), with the official NuGet vulnerability feed replaced by a fake
/// handler and optional basic-auth credentials.
/// </summary>
public sealed class SecurityDashboardApplication : BaGetterApplication
{
    private readonly FakeFeedHttpHandler _feed;

    public SecurityDashboardApplication(
        ITestOutputHelper output,
        FakeFeedHttpHandler feed,
        bool configureCredentials,
        bool disableScheduledScan = false)
        : base(output, inMemoryConfiguration: ConfigureCredentials(configureCredentials))
    {
        _feed = feed ?? new FakeFeedHttpHandler();
        DisableScheduledScan = disableScheduledScan;
        Client = CreateClient();
    }

    public FakeFeedHttpHandler Feed => _feed;

    public HttpClient Client { get; }

    private bool DisableScheduledScan { get; }

    private static Action<Dictionary<string, string>> ConfigureCredentials(bool configureCredentials)
    {
        if (!configureCredentials)
        {
            return null;
        }

        return dict =>
        {
            dict.Add("Authentication:Credentials:0:Username", "username");
            dict.Add("Authentication:Credentials:0:Password", "password");
        };
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureServices(services =>
        {
            // Replace the official feed's HTTP responses without touching the
            // real scanner implementation.
            services.AddHttpClient(NuGetVulnerabilityFeed.HttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => _feed);

            if (DisableScheduledScan)
            {
                // Remove the periodic scan for tests that observe the
                // "no scan has completed yet" state deterministically.
                var scheduled = services
                    .Where(s => s.ServiceType == typeof(IHostedService) &&
                                s.ImplementationType == typeof(VulnerabilityScanBackgroundService))
                    .ToList();
                foreach (var descriptor in scheduled)
                {
                    services.Remove(descriptor);
                }
            }
        });
    }

    /// <summary>Runs the real scanner once, in the test, deterministically.</summary>
    public async Task RunScanAsync()
    {
        var scanner = Services.GetRequiredService<HostedVulnerabilityService>();
        await scanner.RefreshAsync(CancellationToken.None);
    }

    public async Task<string> GetStringAsync(string url)
    {
        using var response = await Client.GetAsync(url);
        return await response.Content.ReadAsStringAsync();
    }

    public async Task<HttpResponseMessage> GetAsync(string url)
    {
        return await Client.GetAsync(url);
    }

    public HttpResponseMessage SendPostToVulnerabilities(string token, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "vulnerabilities?handler=Refresh");
        request.Content = new FormUrlEncodedContent(
            new Dictionary<string, string> { ["__RequestVerificationToken"] = token });
        if (!string.IsNullOrEmpty(cookie))
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }

        // A client that does not follow redirects, so the 302 is observable.
        using var redirectClient = CreateClientWithoutAutoRedirect();
        return redirectClient.SendAsync(request).GetAwaiter().GetResult();
    }

    public async Task<(string Token, string Cookie)> GetAntiforgeryTokenAsync(string url)
    {
        using var response = await Client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        var match = Regex.Match(
            content,
            "name\\s*=\\s*\"__RequestVerificationToken\"[^>]*value\\s*=\\s*\"(?<token>[^\"]+)\"|value\\s*=\\s*\"(?<token2>[^\"]+)\"\\s*name\\s*=\\s*\"__RequestVerificationToken\"");
        var token = match.Success
            ? (match.Groups["token"].Value.Length > 0
                ? match.Groups["token"].Value
                : match.Groups["token2"].Value)
            : throw new InvalidOperationException("The /vulnerabilities page must emit an antiforgery token field.");

        string cookie = null;
        if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            cookie = cookies.FirstOrDefault(c => c.Contains("Antiforgery", StringComparison.OrdinalIgnoreCase))
                ?.Split(';')[0];
        }

        return (token, cookie);
    }

    private HttpClient CreateClientWithoutAutoRedirect()
    {
        var options = new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = Client.BaseAddress,
            AllowAutoRedirect = false
        };
        return CreateClient(options);
    }
}

internal static class SecurityDashboardTestExtensions
{
    public static void SetBasicCredentials(this HttpClient client, string username, string password)
    {
        client.DefaultRequestHeaders.Authorization = new(
            Authentication.AuthenticationConstants.NugetBasicAuthenticationScheme,
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}")));
    }
}

/// <summary>
/// Builds a minimal in-memory .nupkg stream: a zip archive with a single
/// .nuspec entry describing the package and its declared dependencies.
/// </summary>
public static class PackageStreamBuilder
{
    public sealed record Dependency(string Id, string VersionRange, string TargetFramework);

    public static MemoryStream Build(string id, string version, params Dependency[] dependencies)
    {
        var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            var nuspec = archive.CreateEntry(id + ".nuspec");
            using (var writer = new StreamWriter(nuspec.Open(), new UTF8Encoding(false)))
            {
                writer.Write(BuildNuspecXml(id, version, dependencies));
            }
        }

        stream.Position = 0;
        return stream;
    }

    private static string BuildNuspecXml(string id, string version, Dependency[] dependencies)
    {
        var builder = new StringBuilder();
        builder.Append(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<package xmlns=\"http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd\">" +
            "<metadata>");
        builder.Append($"<id>{id}</id><version>{version}</version>");
        builder.Append("<authors>Test author</authors><description>Test description</description>");
        builder.Append("<dependencies>");
        builder.Append("<group targetFramework=\"net9.0\">");
        foreach (var dependency in dependencies)
        {
            builder.Append(
                $"<dependency id=\"{dependency.Id}\" version=\"{dependency.VersionRange}\" />");
        }
        builder.Append("</group></dependencies>");
        builder.Append("</metadata></package>");
        return builder.ToString();
    }
}
