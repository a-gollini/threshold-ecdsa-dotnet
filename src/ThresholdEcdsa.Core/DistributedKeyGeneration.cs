using System.Numerics;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace ThresholdEcdsa.Core;

/// <summary>
/// What a single party holds after key generation. <paramref name="PublicShares"/> holds the public image
/// x_j * G of every party's share (entry j-1 for party j): it is public and lets anyone check proofs about shares.
/// </summary>
public sealed record KeyShare(int Index, BigInteger SecretShare, ECPoint PublicKey, IReadOnlyList<ECPoint> PublicShares)
{
    public ECPoint PublicShareOf(int index) => PublicShares[index - 1];
}

public sealed class DkgComplaintException(int dealer, int recipient)
    : Exception($"Party {recipient} received an invalid share from party {dealer}.")
{
    public int Dealer { get; } = dealer;
    public int Recipient { get; } = recipient;
}

/// <summary>
/// Feldman-VSS based distributed key generation (the Joint-Feldman protocol).
/// Every party deals a random secret; the group key is the sum of all dealt secrets,
/// so no party (and no dealer) ever knows the full private key.
/// This in-process simulation stands in for the network round: it is the protocol logic only.
/// </summary>
public static class DistributedKeyGeneration
{
    public static IReadOnlyList<KeyShare> Run(int threshold, int parties)
    {
        // Round 1: each party deals its own random contribution with Feldman commitments.
        var dealings = Enumerable.Range(1, parties)
            .Select(_ => Shamir.Deal(Curve.RandomScalar(), threshold, parties))
            .ToList();

        // Round 2: each recipient verifies every sub-share it received, then sums them.
        var secretShares = new BigInteger[parties];
        for (var recipient = 0; recipient < parties; recipient++)
        {
            var sum = BigInteger.Zero;
            for (var dealer = 0; dealer < parties; dealer++)
            {
                var received = dealings[dealer].Shares[recipient];
                if (!Shamir.Verify(received, dealings[dealer].Commitments))
                    throw new DkgComplaintException(dealer + 1, recipient + 1);
                sum += received.Value;
            }
            secretShares[recipient] = Curve.Mod(sum);
        }

        // Summing every dealer's commitments coefficient-wise gives commitments to the group polynomial.
        // Its constant term is the group public key, and evaluating it at i gives party i's public share.
        var groupCommitments = new FeldmanCommitments(Enumerable.Range(0, threshold)
            .Select(j => dealings.Select(d => d.Commitments.Coefficients[j]).Aggregate((a, b) => a.Add(b)).Normalize())
            .ToList());
        var publicKey = groupCommitments.PublicKey;
        var publicShares = Enumerable.Range(1, parties)
            .Select(i => Shamir.PublicShare(i, groupCommitments))
            .ToList();

        return secretShares
            .Select((s, i) => new KeyShare(i + 1, s, publicKey, publicShares))
            .ToList();
    }
}
