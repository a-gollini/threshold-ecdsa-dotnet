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

/// <summary>
/// One dealer's round-1 output: Feldman-verifiable shares for everyone, plus a proof that the dealer knows the
/// secret behind its constant-term commitment. Commitments and proof are broadcast; share i goes to party i.
/// </summary>
public sealed record Dealing(int Dealer, DealtSecret Secret, SchnorrProof Proof);

/// <summary>
/// Evidence against a dealer: the share a recipient received and the dealer's broadcast commitments.
/// Anyone can check it, so a false accusation is detectable: it is justified only if the share really fails
/// Feldman verification. (A real deployment would also need the share to be authenticated as coming from the dealer.)
/// </summary>
public sealed record Complaint(int Dealer, int Recipient, Share Share, FeldmanCommitments Commitments)
{
    public bool IsJustified => !Shamir.Verify(Share, Commitments);
}

public sealed class DkgComplaintException(Complaint complaint)
    : Exception($"Party {complaint.Recipient} received an invalid share from party {complaint.Dealer}.")
{
    public Complaint Complaint { get; } = complaint;
    public int Dealer => Complaint.Dealer;
    public int Recipient => Complaint.Recipient;
}

/// <summary>A dealer's broadcast is malformed or its proof of knowledge does not verify.</summary>
public sealed class DkgInvalidDealingException(int dealer, string reason)
    : Exception($"Party {dealer} sent an invalid dealing: {reason}.")
{
    public int Dealer { get; } = dealer;
}

/// <summary>
/// Feldman-VSS based distributed key generation (the Joint-Feldman protocol), hardened with proofs of knowledge.
/// Every party deals a random secret; the group key is the sum of all dealt secrets,
/// so no party (and no dealer) ever knows the full private key.
///
/// Each dealer proves it knows the secret behind its commitment C_0. Without this, the last dealer could pick
/// C_0 = target - (sum of the others) and steer the group key to a value it does not know the discrete log of
/// (a rogue-key attack). With the proof it cannot, because it does not know the discrete log of that C_0.
/// The proof does not prevent the key-distribution bias of Gennaro et al. (see the README).
///
/// This in-process simulation stands in for the network rounds: it is the protocol logic only.
/// </summary>
public static class DistributedKeyGeneration
{
    public static IReadOnlyList<KeyShare> Run(int threshold, int parties) =>
        Complete(Enumerable.Range(1, parties).Select(dealer => Deal(dealer, threshold, parties)).ToList(), threshold, parties);

    /// <summary>Round 1 for one party: deal a fresh random secret and prove knowledge of it.</summary>
    public static Dealing Deal(int dealer, int threshold, int parties)
    {
        var secret = Curve.RandomScalar();
        return new Dealing(dealer, Shamir.Deal(secret, threshold, parties), SchnorrProof.Prove(secret, Context(dealer, threshold, parties)));
    }

    /// <summary>Round 2: check every broadcast and every received share, then derive each party's key share.</summary>
    public static IReadOnlyList<KeyShare> Complete(IReadOnlyList<Dealing> dealings, int threshold, int parties)
    {
        if (dealings.Count != parties || !dealings.Select(d => d.Dealer).SequenceEqual(Enumerable.Range(1, parties)))
            throw new ArgumentException("Expected exactly one dealing from each party, in order.", nameof(dealings));

        foreach (var dealing in dealings)
        {
            if (dealing.Secret.Commitments.Coefficients.Count != threshold || dealing.Secret.Shares.Count != parties)
                throw new DkgInvalidDealingException(dealing.Dealer, "wrong number of commitments or shares");
            if (!dealing.Proof.Verify(dealing.Secret.Commitments.PublicKey, Context(dealing.Dealer, threshold, parties)))
                throw new DkgInvalidDealingException(dealing.Dealer, "proof of knowledge does not verify");
        }

        // Each recipient verifies every sub-share it received, then sums them.
        var secretShares = new BigInteger[parties];
        for (var recipient = 0; recipient < parties; recipient++)
        {
            var sum = BigInteger.Zero;
            foreach (var dealing in dealings)
            {
                var received = dealing.Secret.Shares[recipient];
                if (!Shamir.Verify(received, dealing.Secret.Commitments))
                    throw new DkgComplaintException(new Complaint(dealing.Dealer, recipient + 1, received, dealing.Secret.Commitments));
                sum += received.Value;
            }
            secretShares[recipient] = Curve.Mod(sum);
        }

        // Summing every dealer's commitments coefficient-wise gives commitments to the group polynomial.
        // Its constant term is the group public key, and evaluating it at i gives party i's public share.
        var groupCommitments = new FeldmanCommitments(Enumerable.Range(0, threshold)
            .Select(j => dealings.Select(d => d.Secret.Commitments.Coefficients[j]).Aggregate((a, b) => a.Add(b)).Normalize())
            .ToList());
        var publicKey = groupCommitments.PublicKey;
        var publicShares = Enumerable.Range(1, parties)
            .Select(i => Shamir.PublicShare(i, groupCommitments))
            .ToList();

        return secretShares
            .Select((s, i) => new KeyShare(i + 1, s, publicKey, publicShares))
            .ToList();
    }

    private static string Context(int dealer, int threshold, int parties) => $"dkg|{dealer}|{threshold}|{parties}";
}
