using System.Numerics;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace ThresholdEcdsa.Core;

/// <summary>Round 1: a party's share u_i = k_i * w_i of k*w, with a proof that it is the right product.</summary>
public sealed record RoundOneMessage(int Index, BigInteger Product, DleqProof Proof);

/// <summary>Round 2: a party's partial signature s_i, with a proof that it was computed from its real shares.</summary>
public sealed record RoundTwoMessage(int Index, BigInteger Partial, DleqProof Proof);

/// <summary>A party sent a message whose proof does not verify: the culprit is identified.</summary>
public sealed class SigningAbortException(int party, string step)
    : Exception($"Party {party} sent an invalid {step}.")
{
    public int Party { get; } = party;
}

/// <summary>The random values made the signature degenerate (r, k*w or s is zero): retry with fresh ones.</summary>
public sealed class DegenerateNonceException() : Exception("Degenerate nonce; retry with fresh randomness.");

/// <summary>
/// One threshold signing run with verifiable partial results, simulated in a single process.
/// Every party's public shares are known from the DKGs: K_i = k_i*G (nonce), W_i = w_i*G (blinding),
/// X_i = x_i*G (key). Nothing a party sends can be wrong without being caught:
///
///   Round 1  party i sends u_i = k_i*w_i.   Anyone computes U_i = u_i*G. The proof shows
///            log_G(W_i) = log_{K_i}(U_i) = w_i, i.e. U_i = w_i*K_i, so u_i really is k_i*w_i.
///   Round 2  party i sends s_i = w_i * (kw)^-1 * (m + r*x_i). Anyone derives
///            T_i = r^-1 * (kw * s_i * G - m * W_i), which equals (w_i*x_i)*G iff s_i is correct.
///            The proof shows log_G(W_i) = log_{X_i}(T_i) = w_i, tying s_i to the same blinding share.
///
/// A failed proof raises <see cref="SigningAbortException"/> naming the party (identifiable abort).
/// </summary>
public sealed class SigningSession
{
    private readonly IReadOnlyList<KeyShare> _signers;
    private readonly IReadOnlyList<KeyShare> _nonce;
    private readonly IReadOnlyList<KeyShare> _blind;
    private readonly IReadOnlyList<int> _indices;
    private readonly string _messageTag;
    private readonly BigInteger _m;
    private readonly BigInteger _r;
    private BigInteger _kw;
    private BigInteger _kwInverse;

    /// <param name="signers">The signing parties' key shares (exactly 2t-1 of them).</param>
    /// <param name="nonce">Their shares of the nonce k (from a fresh DKG), in the same order.</param>
    /// <param name="blind">Their shares of the blinding value w (from a fresh DKG), in the same order.</param>
    public SigningSession(
        IReadOnlyList<KeyShare> signers, IReadOnlyList<KeyShare> nonce, IReadOnlyList<KeyShare> blind,
        ReadOnlySpan<byte> messageHash)
    {
        _signers = signers;
        _nonce = nonce;
        _blind = blind;
        _indices = signers.Select(s => s.Index).ToList();
        _messageTag = Convert.ToHexString(messageHash);
        _m = ThresholdSigner.HashToScalar(messageHash);

        // R = k*G is public (the DKG public key of the nonce), and r is its x coordinate.
        _r = Curve.Mod(Curve.FromBc(nonce[0].PublicKey.AffineXCoord.ToBigInteger()));
        if (_r.IsZero) throw new DegenerateNonceException();
    }

    public IReadOnlyList<RoundOneMessage> RoundOne() =>
        _signers.Select((signer, i) => new RoundOneMessage(
            signer.Index,
            Curve.Mod(_nonce[i].SecretShare * _blind[i].SecretShare),
            DleqProof.Prove(_blind[i].SecretShare, Curve.G, _nonce[i].PublicShareOf(signer.Index), ContextOne(signer.Index))))
        .ToList();

    /// <summary>Verifies every round-1 message, opens k*w, and returns each party's round-2 message.</summary>
    public IReadOnlyList<RoundTwoMessage> RoundTwo(IReadOnlyList<RoundOneMessage> messages)
    {
        CheckSenders(messages.Select(x => x.Index));
        for (var i = 0; i < messages.Count; i++)
        {
            var index = _indices[i];
            var product = Curve.MultiplyBase(messages[i].Product);
            if (!messages[i].Proof.Verify(
                    Curve.G, _blind[i].PublicShareOf(index), _nonce[i].PublicShareOf(index), product, ContextOne(index)))
                throw new SigningAbortException(index, "nonce product");
        }

        _kw = Interpolate(messages.Select(x => x.Product));
        if (_kw.IsZero) throw new DegenerateNonceException();
        _kwInverse = Curve.Inverse(_kw);

        return _signers.Select((signer, i) =>
        {
            var kInverseShare = Curve.Mod(_blind[i].SecretShare * _kwInverse);
            var partial = Curve.Mod(kInverseShare * (_m + _r * signer.SecretShare));
            var proof = DleqProof.Prove(
                _blind[i].SecretShare, Curve.G, signer.PublicShareOf(signer.Index), ContextTwo(signer.Index));
            return new RoundTwoMessage(signer.Index, partial, proof);
        }).ToList();
    }

    /// <summary>Verifies every partial signature and interpolates the final low-s signature.</summary>
    public EcdsaSignature Finish(IReadOnlyList<RoundTwoMessage> messages)
    {
        CheckSenders(messages.Select(x => x.Index));
        var rInverse = Curve.Inverse(_r);
        for (var i = 0; i < messages.Count; i++)
        {
            var index = _indices[i];
            var blindPublic = _blind[i].PublicShareOf(index);
            // T_i = r^-1 * (kw * s_i * G - m * W_i), which is (w_i * x_i) * G exactly when s_i is correct.
            var derived = Curve.MultiplyBase(_kw * messages[i].Partial * rInverse)
                .Subtract(Curve.Multiply(blindPublic, _m * rInverse));
            if (!messages[i].Proof.Verify(Curve.G, blindPublic, _signers[i].PublicShareOf(index), derived, ContextTwo(index)))
                throw new SigningAbortException(index, "partial signature");
        }

        var s = Interpolate(messages.Select(x => x.Partial));
        if (s.IsZero) throw new DegenerateNonceException();

        // Normalise to low-s (BIP-62 / Bitcoin style) so signatures are non-malleable.
        if (s > Curve.Order / 2) s = Curve.Order - s;
        return new EcdsaSignature(_r, s);
    }

    private string ContextOne(int index) => $"round1|{index}|{_messageTag}";

    private string ContextTwo(int index) => $"round2|{index}|{_messageTag}";

    private void CheckSenders(IEnumerable<int> senders)
    {
        if (!senders.SequenceEqual(_indices))
            throw new ArgumentException("Messages must come from the signing parties, in order.");
    }

    private BigInteger Interpolate(IEnumerable<BigInteger> values) =>
        Curve.Mod(values
            .Select((v, i) => v * Shamir.LagrangeCoefficientAtZero(_indices[i], _indices))
            .Aggregate(BigInteger.Zero, (a, b) => a + b));
}
