using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace ThresholdEcdsa.Core;

/// <summary>
/// Non-interactive Chaum-Pedersen proof that two points share the same discrete logarithm:
/// P1 = w * B1 and P2 = w * B2 for one secret w, without revealing w. Made non-interactive with Fiat-Shamir.
///
/// The prover commits to V1 = v*B1, V2 = v*B2 for a random v, derives the challenge c = H(statement, V1, V2)
/// and answers z = v + c*w. The verifier recomputes V1 = z*B1 - c*P1 and V2 = z*B2 - c*P2 and checks the hash.
/// </summary>
public sealed record DleqProof(BigInteger Challenge, BigInteger Response)
{
    private const string Domain = "threshold-ecdsa/dleq/v1";

    /// <param name="context">Binds the proof to one protocol step so it cannot be replayed elsewhere.</param>
    public static DleqProof Prove(BigInteger secret, ECPoint base1, ECPoint base2, string context)
    {
        var public1 = Curve.Multiply(base1, secret);
        var public2 = Curve.Multiply(base2, secret);
        var nonce = Curve.RandomScalar();
        var challenge = ComputeChallenge(
            base1, public1, base2, public2, Curve.Multiply(base1, nonce), Curve.Multiply(base2, nonce), context);
        return new DleqProof(challenge, Curve.Mod(nonce + challenge * secret));
    }

    public bool Verify(ECPoint base1, ECPoint public1, ECPoint base2, ECPoint public2, string context)
    {
        var commitment1 = Curve.Multiply(base1, Response).Subtract(Curve.Multiply(public1, Challenge));
        var commitment2 = Curve.Multiply(base2, Response).Subtract(Curve.Multiply(public2, Challenge));
        return Challenge == ComputeChallenge(base1, public1, base2, public2, commitment1, commitment2, context);
    }

    private static BigInteger ComputeChallenge(params object[] parts)
    {
        var input = new List<byte>(Encoding.UTF8.GetBytes(Domain));
        foreach (var part in parts)
            input.AddRange(part is ECPoint point
                ? point.Normalize().GetEncoded(compressed: true)
                : Encoding.UTF8.GetBytes((string)part));
        return Curve.Mod(new BigInteger(SHA256.HashData(input.ToArray()), isUnsigned: true, isBigEndian: true));
    }
}
