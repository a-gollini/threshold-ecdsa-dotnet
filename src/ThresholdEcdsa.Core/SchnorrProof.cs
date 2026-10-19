using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace ThresholdEcdsa.Core;

/// <summary>
/// Non-interactive Schnorr proof of knowledge of the discrete logarithm of a public point P = x*G
/// (Fiat-Shamir). The prover commits to R = v*G, derives c = H(P, R, context) and answers z = v + c*x;
/// the verifier recomputes R = z*G - c*P and checks the hash.
/// </summary>
public sealed record SchnorrProof(BigInteger Challenge, BigInteger Response)
{
    private const string Domain = "threshold-ecdsa/schnorr/v1";

    /// <param name="context">Binds the proof to one protocol step and one prover so it cannot be replayed.</param>
    public static SchnorrProof Prove(BigInteger secret, string context)
    {
        var nonce = Curve.RandomScalar();
        var challenge = ComputeChallenge(Curve.MultiplyBase(secret), Curve.MultiplyBase(nonce), context);
        return new SchnorrProof(challenge, Curve.Mod(nonce + challenge * secret));
    }

    public bool Verify(ECPoint publicPoint, string context)
    {
        var commitment = Curve.MultiplyBase(Response).Subtract(Curve.Multiply(publicPoint, Challenge));
        return Challenge == ComputeChallenge(publicPoint, commitment, context);
    }

    private static BigInteger ComputeChallenge(ECPoint publicPoint, ECPoint commitment, string context)
    {
        var input = new List<byte>(Encoding.UTF8.GetBytes(Domain));
        input.AddRange(publicPoint.Normalize().GetEncoded(compressed: true));
        input.AddRange(commitment.Normalize().GetEncoded(compressed: true));
        input.AddRange(Encoding.UTF8.GetBytes(context));
        return Curve.Mod(new BigInteger(SHA256.HashData(input.ToArray()), isUnsigned: true, isBigEndian: true));
    }
}
