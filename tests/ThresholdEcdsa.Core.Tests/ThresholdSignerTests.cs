using System.Security.Cryptography;
using System.Text;
using ThresholdEcdsa.Core;

namespace ThresholdEcdsa.Core.Tests;

public class ThresholdSignerTests
{
    private static byte[] Hash(string message) => SHA256.HashData(Encoding.UTF8.GetBytes(message));

    [Theory]
    [InlineData(2, 3)]
    [InlineData(2, 5)]
    [InlineData(3, 5)]
    public void ThresholdSignature_VerifiesAsStandardEcdsa(int threshold, int parties)
    {
        var keys = DistributedKeyGeneration.Run(threshold, parties);
        var hash = Hash("pay 1 BTC to alice");

        var signature = ThresholdSigner.Sign(keys, threshold, hash);

        Assert.True(ThresholdSigner.Verify(keys[0].PublicKey, hash, signature));
    }

    [Fact]
    public void Signature_DoesNotVerifyForADifferentMessage()
    {
        var keys = DistributedKeyGeneration.Run(2, 3);
        var signature = ThresholdSigner.Sign(keys, 2, Hash("message A"));

        Assert.False(ThresholdSigner.Verify(keys[0].PublicKey, Hash("message B"), signature));
    }

    [Fact]
    public void Signature_IsLowS()
    {
        var keys = DistributedKeyGeneration.Run(2, 3);

        for (var i = 0; i < 20; i++)
            Assert.True(ThresholdSigner.Sign(keys, 2, Hash($"m{i}")).S <= Curve.Order / 2);
    }

    [Fact]
    public void TooFewSigners_AreRejected()
    {
        var keys = DistributedKeyGeneration.Run(3, 5);

        Assert.Throws<ArgumentException>(() => ThresholdSigner.Sign(keys.Take(4).ToList(), 3, Hash("x")));
    }
}
