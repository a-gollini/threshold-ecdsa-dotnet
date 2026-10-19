using System.Numerics;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace ThresholdEcdsa.Core;

public sealed record EcdsaSignature(BigInteger R, BigInteger S);

/// <summary>
/// Educational threshold ECDSA over secp256k1, simulated in a single process.
///
/// Signing needs 2t-1 online parties, where t is the DKG threshold:
///   1. Nonce k and blinding value w are generated with the DKG (shares of degree t-1).
///   2. R = k*G is opened from the k shares and r = R.x mod n.
///   3. k*w is opened by interpolating the products k_i*w_i (degree 2t-2). Since w is uniform and
///      secret, k*w reveals nothing about k, and k^-1 = w * (k*w)^-1 gives shares of k^-1.
///   4. Each party sends s_i = kinv_i * (m + r*x_i), a share of s = k^-1 (m + r x) of degree 2t-2.
///   5. s is interpolated from the 2t-1 partial signatures.
/// No step reconstructs k or the private key x.
/// </summary>
public static class ThresholdSigner
{
    public static EcdsaSignature Sign(
        IReadOnlyList<KeyShare> signers, int threshold, ReadOnlySpan<byte> messageHash)
    {
        var required = 2 * threshold - 1;
        if (signers.Count < required)
            throw new ArgumentException($"At least {required} signers are required for threshold {threshold}.");
        signers = signers.Take(required).ToList();
        var indices = signers.Select(s => s.Index).ToList();
        var parties = signers.Max(s => s.Index);

        while (true)
        {
            // Fresh nonce and blinding shares for the participating parties. A real deployment would
            // run the DKG among the signers over the network; here we reuse the in-process simulation.
            var nonce = Select(DistributedKeyGeneration.Run(threshold, parties), indices);
            var blind = Select(DistributedKeyGeneration.Run(threshold, parties), indices);

            try
            {
                var session = new SigningSession(signers, nonce, blind, messageHash);
                return session.Finish(session.RoundTwo(session.RoundOne()));
            }
            catch (DegenerateNonceException)
            {
                // Probability about 2^-256 per attempt; draw fresh randomness.
            }
        }
    }

    public static bool Verify(Org.BouncyCastle.Math.EC.ECPoint publicKey, ReadOnlySpan<byte> messageHash, EcdsaSignature signature)
    {
        var verifier = new ECDsaSigner();
        verifier.Init(false, new ECPublicKeyParameters(publicKey, Curve.Domain));
        return verifier.VerifySignature(messageHash.ToArray(), Curve.ToBc(signature.R), Curve.ToBc(signature.S));
    }

    internal static BigInteger HashToScalar(ReadOnlySpan<byte> hash) =>
        Curve.Mod(new BigInteger(hash[..Math.Min(hash.Length, 32)], isUnsigned: true, isBigEndian: true));

    private static List<KeyShare> Select(IReadOnlyList<KeyShare> all, IReadOnlyList<int> indices) =>
        indices.Select(i => all[i - 1]).ToList();
}
