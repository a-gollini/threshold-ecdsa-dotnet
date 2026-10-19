using ThresholdEcdsa.Core;

namespace ThresholdEcdsa.Core.Tests;

public class ShamirTests
{
    [Fact]
    public void AnyThresholdSubset_ReconstructsSecret()
    {
        var secret = Curve.RandomScalar();
        var dealt = Shamir.Deal(secret, threshold: 3, parties: 5);

        foreach (var subset in new[] { new[] { 0, 1, 2 }, new[] { 1, 3, 4 }, new[] { 0, 2, 4 } })
            Assert.Equal(secret, Shamir.Reconstruct(subset.Select(i => dealt.Shares[i]).ToList()));
    }

    [Fact]
    public void BelowThreshold_DoesNotReconstructSecret()
    {
        var secret = Curve.RandomScalar();
        var dealt = Shamir.Deal(secret, threshold: 3, parties: 5);

        Assert.NotEqual(secret, Shamir.Reconstruct(dealt.Shares.Take(2).ToList()));
    }

    [Fact]
    public void FeldmanVerification_AcceptsValidAndRejectsTamperedShares()
    {
        var dealt = Shamir.Deal(Curve.RandomScalar(), threshold: 2, parties: 4);

        Assert.All(dealt.Shares, s => Assert.True(Shamir.Verify(s, dealt.Commitments)));

        var tampered = dealt.Shares[0] with { Value = Curve.Mod(dealt.Shares[0].Value + 1) };
        Assert.False(Shamir.Verify(tampered, dealt.Commitments));
    }

    [Fact]
    public void Commitments_ExposeThePublicKey()
    {
        var secret = Curve.RandomScalar();
        var dealt = Shamir.Deal(secret, 2, 3);

        Assert.Equal(Curve.MultiplyBase(secret), dealt.Commitments.PublicKey);
    }

    [Fact]
    public void DuplicateIndices_AreRejected()
    {
        var dealt = Shamir.Deal(Curve.RandomScalar(), 2, 3);

        Assert.Throws<ArgumentException>(() =>
            Shamir.Reconstruct(new[] { dealt.Shares[0], dealt.Shares[0] }));
    }
}
