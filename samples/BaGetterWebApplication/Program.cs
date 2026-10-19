using BaGetter;
using BaGetter.Authentication;
using BaGetter.Core;
using BaGetter.Web;
using BaGetter.Web.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder();

// This will add the BaGetter services and options to the container.
builder.Services.AddBaGetterWebApplication(bagetter =>
{
    bagetter.AddSqliteDatabase();
    bagetter.AddFileStorage();
});

// Register BaGetter's basic-authentication scheme: its handler yields an
// authenticated anonymous identity while no credentials are configured, and
// enforces HTTP basic authentication once `Authentication:Credentials` exist.
builder.Services.AddAuthentication(options =>
{
    // Register the scheme idempotently for hosting scenarios that reconfigure it.
    if (!options.SchemeMap.ContainsKey(AuthenticationConstants.NugetBasicAuthenticationScheme))
    {
        options.AddScheme<NugetBasicAuthenticationHandler>(
            AuthenticationConstants.NugetBasicAuthenticationScheme,
            AuthenticationConstants.NugetBasicAuthenticationScheme);
        options.DefaultAuthenticateScheme = AuthenticationConstants.NugetBasicAuthenticationScheme;
        options.DefaultChallengeScheme = AuthenticationConstants.NugetBasicAuthenticationScheme;
    }
});

// Register the policy that BaGetter's controllers expect, so their
// [Authorize(Policy = NuGetUserPolicy)] attributes apply in this hosting scenario.
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AuthenticationConstants.NugetUserPolicy, policy =>
    {
        policy.RequireAuthenticatedUser();
    });
});

var app = builder.Build();

if (builder.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseStaticFiles();

// Add BaGetter's endpoints.
new BaGetterEndpointBuilder().MapEndpoints(app);

await app.RunMigrationsAsync();
await app.RunAsync();
