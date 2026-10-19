using System.Numerics;
using ThresholdEcdsa.Core;

namespace ThresholdEcdsa.Core.Tests;

public class DistributedKeyGenerationTests
{
    [Fact]
    public void AnyThresholdSubset_RecoversTheKeyBehindThePublicKey()
    {
        var keys = DistributedKeyGeneration.Run(threshold: 3, parties: 5);

        foreach (var subset in new[] { new[] { 0, 1, 2 }, new[] { 2, 3, 4 }, new[] { 0, 2, 4 } })
        {
            var shares = subset.Select(i => new Share(keys[i].Index, keys[i].SecretShare)).ToList();
            var secret = Shamir.Reconstruct(shares);

            Assert.Equal(keys[0].PublicKey, Curve.MultiplyBase(secret));
        }
    }

    [Fact]
    public void AllPartiesAgreeOnThePublicKey()
    {
        var keys = DistributedKeyGeneration.Run(2, 4);

        Assert.All(keys, k => Assert.Equal(keys[0].PublicKey, k.PublicKey));
    }

    [Fact]
    public void DifferentSubsets_RecoverTheSameKey()
    {
        var keys = DistributedKeyGeneration.Run(2, 4);

        BigInteger Recover(params int[] i) =>
            Shamir.Reconstruct(i.Select(x => new Share(keys[x].Index, keys[x].SecretShare)).ToList());

        Assert.Equal(Recover(0, 1), Recover(2, 3));
    }

    [Fact]
    public void InvalidParameters_AreRejected()
    {
        Assert.Throws<ArgumentException>(() => DistributedKeyGeneration.Run(threshold: 4, parties: 3));
    }
}
