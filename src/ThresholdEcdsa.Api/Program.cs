using System.Globalization;
using System.Numerics;
using ThresholdEcdsa.Api;
using ThresholdEcdsa.Core;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOpenApi();
builder.Services.AddSingleton<IKeyService, KeyService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
    app.MapOpenApi();

var keys = app.MapGroup("/keys").WithTags("Keys");

keys.MapPost("/", (CreateKeyRequest request, IKeyService service) =>
{
    if (request.Threshold < 1 || request.Parties < 2 * request.Threshold - 1 || request.Parties > 20)
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["parties"] = [$"parties must be between {2 * request.Threshold - 1} (2t-1, needed to sign) and 20, and threshold must be >= 1."]
        });

    var key = service.CreateKey(request.Threshold, request.Parties);
    return Results.Created($"/keys/{key.Id}", ToResponse(key));
}).WithSummary("Run distributed key generation among simulated parties.");

keys.MapGet("/{id:guid}", (Guid id, IKeyService service) =>
    service.Find(id) is { } key ? Results.Ok(ToResponse(key)) : Results.NotFound())
    .WithSummary("Get the public information of a generated key.");

keys.MapPost("/{id:guid}/sign", (Guid id, SignRequest request, IKeyService service) =>
{
    if (service.Find(id) is not { } key) return Results.NotFound();
    if (string.IsNullOrEmpty(request.Message))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["message"] = ["message is required."] });

    var signature = service.Sign(key, request.Message);
    return Results.Ok(new SignatureResponse(
        Hex(signature.R), Hex(signature.S), Convert.ToHexString(KeyService.Hash(request.Message)).ToLowerInvariant()));
}).WithSummary("Sign SHA-256(message) with a threshold of parties.");

keys.MapPost("/{id:guid}/verify", (Guid id, VerifyRequest request, IKeyService service) =>
{
    if (service.Find(id) is not { } key) return Results.NotFound();
    if (!TryParse(request.R, out var r) || !TryParse(request.S, out var s))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["signature"] = ["r and s must be hex-encoded."] });

    return Results.Ok(new VerifyResponse(service.Verify(key, request.Message ?? "", new EcdsaSignature(r, s))));
}).WithSummary("Verify a signature with standard ECDSA.");

app.Run();

static KeyResponse ToResponse(StoredKey key) => new(key.Id, key.Threshold, key.Parties, key.PublicKeyHex);

// Fixed-width big-endian hex. BigInteger.ToString("x64") would prepend a sign digit when the top bit is set.
static string Hex(BigInteger value) =>
    Convert.ToHexString(value.ToByteArray(isUnsigned: true, isBigEndian: true)).ToLowerInvariant().PadLeft(64, '0');

static bool TryParse(string? hex, out BigInteger value)
{
    value = default;
    if (string.IsNullOrEmpty(hex) || hex.Length > 64) return false;
    return BigInteger.TryParse("0" + hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
}

public partial class Program;
