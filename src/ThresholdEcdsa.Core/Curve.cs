using System.Numerics;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace ThresholdEcdsa.Core;

/// <summary>secp256k1 parameters and scalar helpers (arithmetic modulo the group order).</summary>
public static class Curve
{
    private static readonly X9ECParameters Params = CustomNamedCurves.GetByName("secp256k1");

    public static ECPoint G => Params.G;

    public static ECDomainParameters Domain { get; } = new(Params.Curve, Params.G, Params.N, Params.H);

    public static BigInteger Order { get; } = ToBigInteger(Params.N);

    public static BigInteger Mod(BigInteger value)
    {
        var r = value % Order;
        return r.Sign < 0 ? r + Order : r;
    }

    public static BigInteger Inverse(BigInteger value) =>
        BigInteger.ModPow(Mod(value), Order - 2, Order);

    /// <summary>Uniform random scalar in [1, n-1] using the OS CSPRNG (rejection sampling).</summary>
    public static BigInteger RandomScalar()
    {
        Span<byte> buffer = stackalloc byte[32];
        while (true)
        {
            RandomNumberGenerator.Fill(buffer);
            var candidate = new BigInteger(buffer, isUnsigned: true, isBigEndian: true);
            if (candidate.Sign > 0 && candidate < Order)
                return candidate;
        }
    }

    public static ECPoint Multiply(ECPoint point, BigInteger scalar) =>
        point.Multiply(ToBc(Mod(scalar))).Normalize();

    public static ECPoint MultiplyBase(BigInteger scalar) => Multiply(G, scalar);

    public static BigInteger FromBc(BcBigInteger value) => ToBigInteger(value);

    private static BigInteger ToBigInteger(BcBigInteger value) =>
        new(value.ToByteArrayUnsigned(), isUnsigned: true, isBigEndian: true);

    public static BcBigInteger ToBc(BigInteger value) =>
        new(1, value.ToByteArray(isUnsigned: true, isBigEndian: true));
}
