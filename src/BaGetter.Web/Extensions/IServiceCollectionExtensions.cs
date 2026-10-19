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
        services.AddSingleton<HostedVulnerabilityService>();
        services.AddHostedService<VulnerabilityScanBackgroundService>();

        var app = services.AddBaGetterApplication(configureAction);

        return services;
    }
}
