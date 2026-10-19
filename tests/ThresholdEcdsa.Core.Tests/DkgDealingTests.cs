using ThresholdEcdsa.Core;

namespace ThresholdEcdsa.Core.Tests;

public class DkgDealingTests
{
    private const int Threshold = 2;
    private const int Parties = 4;

    private static List<Dealing> HonestDealings() =>
        Enumerable.Range(1, Parties).Select(d => DistributedKeyGeneration.Deal(d, Threshold, Parties)).ToList();

    [Fact]
    public void HonestDealings_CompleteAndAgreeOnTheKey()
    {
        var keys = DistributedKeyGeneration.Complete(HonestDealings(), Threshold, Parties);

        Assert.Equal(Parties, keys.Count);
        Assert.All(keys, k => Assert.Equal(keys[0].PublicKey, k.PublicKey));
    }

    [Fact]
    public void SchnorrProof_VerifiesAndIsBoundToItsContext()
    {
        var secret = Curve.RandomScalar();
        var proof = SchnorrProof.Prove(secret, "dkg|1");

        Assert.True(proof.Verify(Curve.MultiplyBase(secret), "dkg|1"));
        Assert.False(proof.Verify(Curve.MultiplyBase(secret), "dkg|2"));
        Assert.False(proof.Verify(Curve.MultiplyBase(Curve.Mod(secret + 1)), "dkg|1"));
    }

    [Fact]
    public void ProofForADifferentSecret_IsRejected()
    {
        var dealings = HonestDealings();
        dealings[2] = dealings[2] with { Proof = SchnorrProof.Prove(Curve.RandomScalar(), "dkg|3|2|4") };

        var error = Assert.Throws<DkgInvalidDealingException>(() => DistributedKeyGeneration.Complete(dealings, Threshold, Parties));

        Assert.Equal(3, error.Dealer);
    }

    [Fact]
    public void ProofReplayedFromAnotherDealer_IsRejected()
    {
        var dealings = HonestDealings();
        dealings[1] = dealings[1] with { Proof = dealings[0].Proof };

        var error = Assert.Throws<DkgInvalidDealingException>(() => DistributedKeyGeneration.Complete(dealings, Threshold, Parties));

        Assert.Equal(2, error.Dealer);
    }

    [Fact]
    public void RogueKeyAttack_IsRejected()
    {
        // The last dealer tries to steer the group key to a point it does not know the discrete log of,
        // by choosing C_0 = target - (sum of the other C_0). It cannot prove knowledge of that C_0's secret.
        var dealings = HonestDealings();
        var target = Curve.MultiplyBase(Curve.RandomScalar());
        var others = dealings.Take(Parties - 1)
            .Select(d => d.Secret.Commitments.PublicKey).Aggregate((a, b) => a.Add(b));
        var rogue = dealings[^1];
        var coefficients = rogue.Secret.Commitments.Coefficients.ToList();
        coefficients[0] = target.Subtract(others).Normalize();
        dealings[^1] = rogue with { Secret = rogue.Secret with { Commitments = new FeldmanCommitments(coefficients) } };

        var error = Assert.Throws<DkgInvalidDealingException>(() => DistributedKeyGeneration.Complete(dealings, Threshold, Parties));

        Assert.Equal(Parties, error.Dealer);
    }

    [Fact]
    public void MalformedDealing_IsRejected()
    {
        var dealings = HonestDealings();
        var commitments = dealings[0].Secret.Commitments.Coefficients.Take(1).ToList();
        dealings[0] = dealings[0] with { Secret = dealings[0].Secret with { Commitments = new FeldmanCommitments(commitments) } };

        var error = Assert.Throws<DkgInvalidDealingException>(() => DistributedKeyGeneration.Complete(dealings, Threshold, Parties));

        Assert.Equal(1, error.Dealer);
    }

    [Fact]
    public void InvalidShare_ProducesAComplaintThatAnyoneCanCheck()
    {
        var dealings = HonestDealings();
        var shares = dealings[1].Secret.Shares.ToList();
        shares[2] = shares[2] with { Value = Curve.Mod(shares[2].Value + 1) };
        dealings[1] = dealings[1] with { Secret = dealings[1].Secret with { Shares = shares } };

        var error = Assert.Throws<DkgComplaintException>(() => DistributedKeyGeneration.Complete(dealings, Threshold, Parties));

        Assert.Equal((2, 3), (error.Dealer, error.Recipient));
        Assert.True(error.Complaint.IsJustified);
    }

    [Fact]
    public void FalseComplaintAgainstAnHonestDealer_IsNotJustified()
    {
        var dealing = HonestDealings()[0];

        var complaint = new Complaint(1, 2, dealing.Secret.Shares[1], dealing.Secret.Commitments);

        Assert.False(complaint.IsJustified);
    }
}
