using System.Numerics;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace ThresholdEcdsa.Core;

public sealed record Share(int Index, BigInteger Value);

/// <summary>Feldman commitments: C_j = a_j * G for each polynomial coefficient a_j.</summary>
public sealed record FeldmanCommitments(IReadOnlyList<ECPoint> Coefficients)
{
    public ECPoint PublicKey => Coefficients[0];
}

public sealed record DealtSecret(IReadOnlyList<Share> Shares, FeldmanCommitments Commitments);

/// <summary>Shamir secret sharing over the secp256k1 scalar field, with Feldman verifiability.</summary>
public static class Shamir
{
    public static DealtSecret Deal(BigInteger secret, int threshold, int parties)
    {
        if (threshold < 1) throw new ArgumentOutOfRangeException(nameof(threshold));
        if (parties < threshold) throw new ArgumentException("parties must be >= threshold", nameof(parties));

        // f(x) = a_0 + a_1 x + ... + a_{t-1} x^{t-1}, with a_0 = secret.
        var coefficients = new BigInteger[threshold];
        coefficients[0] = Curve.Mod(secret);
        for (var i = 1; i < threshold; i++)
            coefficients[i] = Curve.RandomScalar();

        var shares = Enumerable.Range(1, parties)
            .Select(x => new Share(x, Evaluate(coefficients, x)))
            .ToList();
        var commitments = new FeldmanCommitments(coefficients.Select(Curve.MultiplyBase).ToList());
        return new DealtSecret(shares, commitments);
    }

    /// <summary>Checks s_i * G == sum_j (i^j * C_j).</summary>
    public static bool Verify(Share share, FeldmanCommitments commitments) =>
        Curve.MultiplyBase(share.Value).Equals(PublicShare(share.Index, commitments));

    /// <summary>The public image of party i's share, sum_j (i^j * C_j) = f(i) * G, computable by anyone.</summary>
    public static ECPoint PublicShare(int index, FeldmanCommitments commitments)
    {
        var result = commitments.Coefficients[0];
        var power = BigInteger.One;
        for (var j = 1; j < commitments.Coefficients.Count; j++)
        {
            power = Curve.Mod(power * index);
            result = result.Add(Curve.Multiply(commitments.Coefficients[j], power));
        }
        return result.Normalize();
    }

    public static BigInteger Reconstruct(IReadOnlyList<Share> shares)
    {
        if (shares.Select(s => s.Index).Distinct().Count() != shares.Count)
            throw new ArgumentException("duplicate share indices", nameof(shares));

        var secret = BigInteger.Zero;
        foreach (var share in shares)
            secret += share.Value * LagrangeCoefficientAtZero(share.Index, shares.Select(s => s.Index).ToList());
        return Curve.Mod(secret);
    }

    public static BigInteger LagrangeCoefficientAtZero(int index, IReadOnlyList<int> participants)
    {
        BigInteger numerator = 1, denominator = 1;
        foreach (var j in participants.Where(j => j != index))
        {
            numerator = Curve.Mod(numerator * -j);
            denominator = Curve.Mod(denominator * (index - j));
        }
        return Curve.Mod(numerator * Curve.Inverse(denominator));
    }

    private static BigInteger Evaluate(BigInteger[] coefficients, int x)
    {
        // Horner's method.
        var result = BigInteger.Zero;
        for (var i = coefficients.Length - 1; i >= 0; i--)
            result = Curve.Mod(result * x + coefficients[i]);
        return result;
    }
}
