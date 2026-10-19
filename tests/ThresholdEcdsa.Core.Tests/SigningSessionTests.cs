using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using ThresholdEcdsa.Core;

namespace ThresholdEcdsa.Core.Tests;

public class SigningSessionTests
{
    private const int Threshold = 2;
    private static readonly byte[] Hash = SHA256.HashData(Encoding.UTF8.GetBytes("pay 1 BTC to alice"));

    private static (IReadOnlyList<KeyShare> Keys, SigningSession Session) NewSession(byte[]? hash = null)
    {
        var keys = DistributedKeyGeneration.Run(Threshold, 3);
        var nonce = DistributedKeyGeneration.Run(Threshold, 3);
        var blind = DistributedKeyGeneration.Run(Threshold, 3);
        return (keys, new SigningSession(keys, nonce, blind, hash ?? Hash));
    }

    [Fact]
    public void HonestParties_ProduceAValidSignature()
    {
        var (keys, session) = NewSession();

        var signature = session.Finish(session.RoundTwo(session.RoundOne()));

        Assert.True(ThresholdSigner.Verify(keys[0].PublicKey, Hash, signature));
    }

    [Fact]
    public void PublicShares_MatchTheSecretShares_AndAreSharedByAllParties()
    {
        var keys = DistributedKeyGeneration.Run(3, 5);

        Assert.All(keys, k => Assert.Equal(Curve.MultiplyBase(k.SecretShare), keys[0].PublicShareOf(k.Index)));
        Assert.All(keys, k => Assert.Equal(keys[0].PublicShares, k.PublicShares));
    }

    [Fact]
    public void WrongNonceProduct_IdentifiesTheCheatingParty()
    {
        var (_, session) = NewSession();
        var messages = session.RoundOne().ToList();
        messages[1] = messages[1] with { Product = Curve.Mod(messages[1].Product + 1) };

        var abort = Assert.Throws<SigningAbortException>(() => session.RoundTwo(messages));

        Assert.Equal(2, abort.Party);
    }

    [Fact]
    public void ProofCopiedFromAnotherParty_IsRejected()
    {
        var (_, session) = NewSession();
        var messages = session.RoundOne().ToList();
        messages[2] = messages[2] with { Proof = messages[0].Proof };

        var abort = Assert.Throws<SigningAbortException>(() => session.RoundTwo(messages));

        Assert.Equal(3, abort.Party);
    }

    [Fact]
    public void WrongPartialSignature_IdentifiesTheCheatingParty()
    {
        var (_, session) = NewSession();
        var messages = session.RoundTwo(session.RoundOne()).ToList();
        messages[0] = messages[0] with { Partial = Curve.Mod(messages[0].Partial + 1) };

        var abort = Assert.Throws<SigningAbortException>(() => session.Finish(messages));

        Assert.Equal(1, abort.Party);
    }

    [Fact]
    public void PartyUsingADifferentKeyShareThanItCommittedTo_IsIdentified()
    {
        // Party 2 computes a perfectly well-formed s_2, but from a secret share that does not match
        // its public share from the DKG. Only the proof against the public share can catch this.
        var keys = DistributedKeyGeneration.Run(Threshold, 3);
        var cheater = keys.ToList();
        cheater[1] = cheater[1] with { SecretShare = Curve.RandomScalar() };
        var session = new SigningSession(
            cheater, DistributedKeyGeneration.Run(Threshold, 3), DistributedKeyGeneration.Run(Threshold, 3), Hash);

        var abort = Assert.Throws<SigningAbortException>(() => session.Finish(session.RoundTwo(session.RoundOne())));

        Assert.Equal(2, abort.Party);
    }

    [Fact]
    public void RoundTwoProofIsBoundToTheMessage()
    {
        var (_, first) = NewSession();
        var (_, second) = NewSession(SHA256.HashData(Encoding.UTF8.GetBytes("a different message")));
        var stolen = first.RoundTwo(first.RoundOne());

        // Round-2 messages from one session are never accepted by another.
        second.RoundTwo(second.RoundOne());
        Assert.Throws<SigningAbortException>(() => second.Finish(stolen));
    }

    [Fact]
    public void MessagesFromTheWrongParties_AreRejected()
    {
        var (_, session) = NewSession();
        var messages = session.RoundOne().Reverse().ToList();

        Assert.Throws<ArgumentException>(() => session.RoundTwo(messages));
    }
}
