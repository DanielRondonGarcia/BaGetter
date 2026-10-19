using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Serialization;
using BaGetter.Authentication;
using BaGetter.Core;
using BaGetter.Web;
using BaGetter.Web.Authentication;
using BaGetter.Web.Helper;
using BaGetter.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BaGetter;

public static class IServiceCollectionExtensions
{
    public static IServiceCollection AddBaGetterWebApplication(
        this IServiceCollection services,
        Action<BaGetterApplication> configureAction)
    {
        services
            .AddRouting(options => options.LowercaseUrls = true)
            .AddControllers()
            .AddApplicationPart(typeof(PackageContentController).Assembly)
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
            });

        services.AddRazorPages();

        services.AddHttpContextAccessor();
        services.AddTransient<IUrlGenerator, BaGetterUrlGenerator>();

        services.AddSingleton(ApplicationVersionHelper.GetVersion());

        // Hosted vulnerability scanning: an automatic scan (startup + hourly)
        // builds a read-only snapshot of the packages this server hosts, checked
        // against the official NuGet vulnerability feed. The dashboard and the
        // per-package accordion read HostedVulnerabilityService.Current; the
        // dashboard's Rescan form calls RefreshAsync. No report file import.
        // The feed is served gzip-compressed by nuget.org, so the handler must
        // decode standard compressed HTTP content (header based, no heuristics).
        services
            .AddHttpClient(NuGetVulnerabilityFeed.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.All
            });
        services.AddSingleton<IHostedPackageReader, HostedPackageReader>();
        services.AddSingleton<NuGetVulnerabilityFeed>();
        // Vulnerability analysis history (Vulnerabilities:History:Path): every
        // successfully completed scan is appended as one immutable JSON
        // snapshot so a UTC date range can later be exported. A missing or
        // unusable path never fails a scan; it only disables archive/export
        // and stays visible through the store's status/LastError.
        services
            .AddOptions<VulnerabilityHistoryOptions>()
            .BindConfiguration("Vulnerabilities:History");
        // Explicit factory: the store takes the bound options VALUE (not the
        // IOptions wrapper), so a real host that resolves the store gets a
        // single dependency graph instead of an unregistered raw options type.
        services.AddSingleton<VulnerabilityHistoryStore>(provider =>
            new VulnerabilityHistoryStore(
                provider.GetRequiredService<IOptions<VulnerabilityHistoryOptions>>().Value,
                provider.GetRequiredService<IHostEnvironment>(),
                provider.GetRequiredService<ILogger<VulnerabilityHistoryStore>>()));
        services.AddSingleton<HostedVulnerabilityService>();
        services.AddHostedService<VulnerabilityScanBackgroundService>();

        var app = services.AddBaGetterApplication(configureAction);

        return services;
    }
}
