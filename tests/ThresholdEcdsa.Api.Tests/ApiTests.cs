using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using ThresholdEcdsa.Api;

namespace ThresholdEcdsa.Api.Tests;

public class ApiTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client = factory.CreateClient();

    private async Task<KeyResponse> CreateKey(int threshold = 2, int parties = 3)
    {
        var response = await _client.PostAsJsonAsync("/keys", new CreateKeyRequest(threshold, parties));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<KeyResponse>())!;
    }

    [Fact]
    public async Task CreateKey_ReturnsCompressedPublicKey()
    {
        var key = await CreateKey();

        Assert.Equal(66, key.PublicKey.Length);
        Assert.Contains(key.PublicKey[..2], new[] { "02", "03" });
    }

    [Fact]
    public async Task SignThenVerify_RoundTrips()
    {
        var key = await CreateKey();

        var signResponse = await _client.PostAsJsonAsync($"/keys/{key.KeyId}/sign", new SignRequest("hello"));
        var signature = (await signResponse.Content.ReadFromJsonAsync<SignatureResponse>())!;

        var ok = await (await _client.PostAsJsonAsync($"/keys/{key.KeyId}/verify", new VerifyRequest("hello", signature.R, signature.S)))
            .Content.ReadFromJsonAsync<VerifyResponse>();
        var tampered = await (await _client.PostAsJsonAsync($"/keys/{key.KeyId}/verify", new VerifyRequest("hellO", signature.R, signature.S)))
            .Content.ReadFromJsonAsync<VerifyResponse>();

        Assert.True(ok!.Valid);
        Assert.False(tampered!.Valid);
    }

    [Fact]
    public async Task Signatures_AreAlways64HexCharacters()
    {
        var key = await CreateKey();

        for (var i = 0; i < 30; i++)
        {
            var response = await _client.PostAsJsonAsync($"/keys/{key.KeyId}/sign", new SignRequest($"message {i}"));
            var signature = (await response.Content.ReadFromJsonAsync<SignatureResponse>())!;

            Assert.Equal(64, signature.R.Length);
            Assert.Equal(64, signature.S.Length);
        }
    }

    [Theory]
    [InlineData(0, 3)]
    [InlineData(3, 4)]
    [InlineData(2, 100)]
    public async Task CreateKey_RejectsInvalidParameters(int threshold, int parties)
    {
        var response = await _client.PostAsJsonAsync("/keys", new CreateKeyRequest(threshold, parties));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task UnknownKey_Returns404()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync($"/keys/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await _client.PostAsJsonAsync($"/keys/{Guid.NewGuid()}/sign", new SignRequest("x"))).StatusCode);
    }

    [Fact]
    public async Task Sign_RequiresMessage()
    {
        var key = await CreateKey();

        var response = await _client.PostAsJsonAsync($"/keys/{key.KeyId}/sign", new SignRequest(""));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Verify_RejectsMalformedHex()
    {
        var key = await CreateKey();

        var response = await _client.PostAsJsonAsync($"/keys/{key.KeyId}/verify", new VerifyRequest("m", "zz", "01"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
