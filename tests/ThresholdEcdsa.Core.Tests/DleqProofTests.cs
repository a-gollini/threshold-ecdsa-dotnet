using ThresholdEcdsa.Core;

namespace ThresholdEcdsa.Core.Tests;

public class DleqProofTests
{
    private static readonly Org.BouncyCastle.Math.EC.ECPoint Base2 = Curve.MultiplyBase(Curve.RandomScalar());

    [Fact]
    public void ValidProof_Verifies()
    {
        var w = Curve.RandomScalar();
        var proof = DleqProof.Prove(w, Curve.G, Base2, "ctx");

        Assert.True(proof.Verify(Curve.G, Curve.MultiplyBase(w), Base2, Curve.Multiply(Base2, w), "ctx"));
    }

    [Fact]
    public void DifferentDiscreteLogs_AreRejected()
    {
        var w = Curve.RandomScalar();
        var proof = DleqProof.Prove(w, Curve.G, Base2, "ctx");
        var wrongSecond = Curve.Multiply(Base2, Curve.Mod(w + 1));

        Assert.False(proof.Verify(Curve.G, Curve.MultiplyBase(w), Base2, wrongSecond, "ctx"));
    }

    [Fact]
    public void ProofIsBoundToItsContext()
    {
        var w = Curve.RandomScalar();
        var proof = DleqProof.Prove(w, Curve.G, Base2, "round1|1");

        Assert.False(proof.Verify(Curve.G, Curve.MultiplyBase(w), Base2, Curve.Multiply(Base2, w), "round1|2"));
    }

    [Fact]
    public void TamperedResponse_IsRejected()
    {
        var w = Curve.RandomScalar();
        var proof = DleqProof.Prove(w, Curve.G, Base2, "ctx");
        var tampered = proof with { Response = Curve.Mod(proof.Response + 1) };

        Assert.False(tampered.Verify(Curve.G, Curve.MultiplyBase(w), Base2, Curve.Multiply(Base2, w), "ctx"));
    }
}
