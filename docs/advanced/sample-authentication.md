# Sample: hosting with NuGet basic authentication

The minimal-hosting sample (`samples/BaGetterWebApplication/Program.cs`) embeds
BaGetter inside an existing ASP.NET Core application. BaGetter's read controllers
(`ServiceIndex`, `Search`, `PackageMetadata`, `PackageContent`, `Symbol`) declare:

```csharp
[Authorize(AuthenticationSchemes = AuthenticationConstants.NugetBasicAuthenticationScheme,
    Policy = AuthenticationConstants.NugetUserPolicy)]
```

Because the sample does not use BaGetter's main `Startup`, it must register the
scheme and policy itself, exactly as shown in the sample's `Program.cs`:

1. `AddAuthentication` registers the `NugetBasicAuthentication` scheme backed by
   `NugetBasicAuthenticationHandler` and sets it as the default authenticate and
   challenge scheme. The registration checks `SchemeMap.ContainsKey` first, so it
   is idempotent for hosting scenarios that reconfigure authentication.
2. `AddAuthorization` registers the `NuGetUserPolicy` policy with
   `RequireAuthenticatedUser()`.

With `WebApplication` (minimal hosting), `UseAuthentication` and `UseAuthorization`
are added automatically when these services are registered, so the sample pipeline
needs no additional middleware.

## Expected behavior

| Configuration | Anonymous request | Valid basic credentials | Invalid basic credentials |
|---|---|---|---|
| No `Authentication:Credentials` configured | `200 OK` | `200 OK` | `200 OK` |
| At least one credential configured | `401` with `WWW-Authenticate: Basic` | `200 OK` | `401` |

The anonymous pass-through is provided by `NugetBasicAuthenticationHandler`
itself (`BaGetterOptions.Authentication.Credentials` empty), not by any
authorization bypass. Do **not** disable the `[Authorize]` attributes or add a
middleware that skips policy evaluation (for example setting an `AllowAnonymous`
context item) to make the sample compile or run — register the scheme and policy
instead.

The behavior above is pinned by `SampleAuthenticationTests` in
`tests/BaGetter.Tests`, which compose the same host registration and pipeline
over HTTP.