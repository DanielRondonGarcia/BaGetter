using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using BaGetter;
using BaGetter.Authentication;
using BaGetter.Core;
using BaGetter.Web;
using BaGetter.Web.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;

namespace BaGetter.Tests;

/// <summary>
/// HTTP integration tests for the minimal-hosting sample authentication model
/// documented in docs/advanced/sample-authentication.md.
///
/// The fixture composes the exact same public service registration and pipeline
/// as <c>samples/BaGetterWebApplication/Program.cs</c>: BaGetter's web application
/// services (Sqlite + file storage), the <see cref="NugetBasicAuthenticationHandler"/>
/// scheme, the <see cref="AuthenticationConstants.NugetUserPolicy"/> policy built with
/// <c>RequireAuthenticatedUser</c>, and the endpoint mapping — with no bypass middleware.
/// </summary>
public class SampleAuthenticationTests
{
    [Fact]
    public async Task AnonymousAccess_WhenNoCredentialsConfigured_ReturnsOk()
    {
        using var app = new SampleWebApplication(output: null, configureCredentials: false);

        // Act
        using var response = await app.Client.GetAsync("v3/index.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AnonymousAccess_WhenCredentialsConfigured_ReturnsUnauthorized()
    {
        using var app = new SampleWebApplication(output: null, configureCredentials: true);

        // Act
        using var response = await app.Client.GetAsync("v3/index.json");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Basic realm=\"NuGet Server\"", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task ValidCredentialsAccess_WhenCredentialsConfigured_ReturnsOk()
    {
        using var app = new SampleWebApplication(output: null, configureCredentials: true);

        // Arrange
        app.Client.DefaultRequestHeaders.Authorization = new(
            AuthenticationConstants.NugetBasicAuthenticationScheme,
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{UserName}:{Password}")));

        // Act
        using var response = await app.Client.GetAsync("v3/index.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task InvalidCredentialsAccess_WhenCredentialsConfigured_ReturnsUnauthorized()
    {
        using var app = new SampleWebApplication(output: null, configureCredentials: true);

        // Arrange
        app.Client.DefaultRequestHeaders.Authorization = new(
            AuthenticationConstants.NugetBasicAuthenticationScheme,
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{UserName}:{Password}x")));

        // Act
        using var response = await app.Client.GetAsync("v3/index.json");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private const string UserName = "username";
    private const string Password = "password";
}

/// <summary>
/// Boots a host composed exactly like the minimal-hosting sample
/// (samples/BaGetterWebApplication/Program.cs), without any authentication bypass.
/// </summary>
public sealed class SampleWebApplication : IDisposable
{
    private readonly IHost _host;
    private readonly string _tempPath;

    public SampleWebApplication(ITestOutputHelper output, bool configureCredentials)
    {
        // Temporary SQLite and package storage paths, outside the repository.
        _tempPath = Path.Combine(Path.GetTempPath(), "BaGetterTests", Guid.NewGuid().ToString("N"));

        var configuration = new Dictionary<string, string>
        {
            { "Database:Type", "Sqlite" },
            { "Database:ConnectionString", $"Data Source={Path.Combine(_tempPath, "BaGetter.db")}" },
            { "Storage:Type", "FileSystem" },
            { "Storage:Path", Path.Combine(_tempPath, "Packages") },
            { "Search:Type", "Database" },
        };

        if (configureCredentials)
        {
            configuration.Add("Authentication:Credentials:0:Username", "username");
            configuration.Add("Authentication:Credentials:0:Password", "password");
        }

        _host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder
                    .UseTestServer()
                    .UseEnvironment("Production")
                    .UseConfiguration(new ConfigurationBuilder()
                        .AddInMemoryCollection(configuration)
                        .Build())
                    .ConfigureLogging(logging =>
                    {
                        logging.ClearProviders();
                        if (output is not null)
                        {
                            logging.AddProvider(new XunitLoggerProvider(output));
                        }
                    })
                    .ConfigureServices(services =>
                    {
                        // This sample mirrors samples/BaGetterWebApplication/Program.cs. Keep both
                        // registrations identical after changing either side.
                        services.AddBaGetterWebApplication(bagetter =>
                        {
                            bagetter.AddSqliteDatabase();
                            bagetter.AddFileStorage();
                        });

                        services.AddAuthentication(options =>
                        {
                            // Idempotent: some hosting scenarios may register the scheme twice.
                            if (!options.SchemeMap.ContainsKey(AuthenticationConstants.NugetBasicAuthenticationScheme))
                            {
                                options.AddScheme<NugetBasicAuthenticationHandler>(
                                    AuthenticationConstants.NugetBasicAuthenticationScheme,
                                    AuthenticationConstants.NugetBasicAuthenticationScheme);
                                options.DefaultAuthenticateScheme = AuthenticationConstants.NugetBasicAuthenticationScheme;
                                options.DefaultChallengeScheme = AuthenticationConstants.NugetBasicAuthenticationScheme;
                            }
                        });

                        services.AddAuthorization(options =>
                        {
                            options.AddPolicy(AuthenticationConstants.NugetUserPolicy, policy =>
                            {
                                policy.RequireAuthenticatedUser();
                            });
                        });
                    })
                    .Configure(app =>
                    {
                        app.UseAuthentication();
                        app.UseRouting();
                        app.UseAuthorization();

                        // Add BaGetter's endpoints.
                        app.UseEndpoints(endpoints => new BaGetterEndpointBuilder().MapEndpoints(endpoints));
                    });
            })
            .Start();

        Client = _host.GetTestClient();
    }

    public HttpClient Client { get; }

    public void Dispose()
    {
        _host.Dispose();
        Client.Dispose();

        try
        {
            if (Directory.Exists(_tempPath))
            {
                Directory.Delete(_tempPath, recursive: true);
            }
        }
        catch (IOException)
        {
            // Best effort cleanup; the directory name was reported if it lingers.
        }
    }
}