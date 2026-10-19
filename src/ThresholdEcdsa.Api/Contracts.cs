namespace ThresholdEcdsa.Api;

public sealed record CreateKeyRequest(int Threshold, int Parties);

public sealed record KeyResponse(Guid KeyId, int Threshold, int Parties, string PublicKey);

public sealed record SignRequest(string Message);

public sealed record SignatureResponse(string R, string S, string MessageHash);

public sealed record VerifyRequest(string Message, string R, string S);

public sealed record VerifyResponse(bool Valid);
