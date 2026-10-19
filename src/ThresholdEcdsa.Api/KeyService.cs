using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using ThresholdEcdsa.Core;

namespace ThresholdEcdsa.Api;

public sealed record StoredKey(Guid Id, int Threshold, IReadOnlyList<KeyShare> Shares)
{
    public int Parties => Shares.Count;
    public string PublicKeyHex => Convert.ToHexString(Shares[0].PublicKey.GetEncoded(compressed: true)).ToLowerInvariant();
}

public interface IKeyService
{
    StoredKey CreateKey(int threshold, int parties);
    StoredKey? Find(Guid id);
    EcdsaSignature Sign(StoredKey key, string message);
    bool Verify(StoredKey key, string message, EcdsaSignature signature);
}

/// <summary>
/// Application layer: orchestrates the Core library. All parties are simulated in-process,
/// so shares live in memory only and are lost on restart (by design for this demo).
/// </summary>
public sealed class KeyService : IKeyService
{
    private readonly ConcurrentDictionary<Guid, StoredKey> _keys = new();

    public StoredKey CreateKey(int threshold, int parties)
    {
        var key = new StoredKey(Guid.NewGuid(), threshold, DistributedKeyGeneration.Run(threshold, parties));
        _keys[key.Id] = key;
        return key;
    }

    public StoredKey? Find(Guid id) => _keys.GetValueOrDefault(id);

    public EcdsaSignature Sign(StoredKey key, string message) =>
        ThresholdSigner.Sign(key.Shares, key.Threshold, Hash(message));

    public bool Verify(StoredKey key, string message, EcdsaSignature signature) =>
        ThresholdSigner.Verify(key.Shares[0].PublicKey, Hash(message), signature);

    public static byte[] Hash(string message) => SHA256.HashData(Encoding.UTF8.GetBytes(message));
}
