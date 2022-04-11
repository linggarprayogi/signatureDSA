package app;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class VerifySignature {

	public static void main(String[] args) throws Exception {
		verifySignature("INV001|0005|", "MCwCFAWxGyDh5J+rEkOcqUbt4Pa4ah51AhR/EZtJXvL3XdcuaFrcqpi9gGaQkQ==",
				"MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAO2VXY74PI9R9JMowqShDSUtCtMgpGNafLucRY9chFMlqpPA/m2lWhf0T7OuftNwY495nj8mBpskiMa/ncIda5Vhi0+/qxY9ZFA3RoOHzLmDeG+BFvlgPL3Il3oYhgtDfttawbNGNOg4KMQLt0jc+6ToDkf91IYZ145uFqG5xGvn");
	}

	public static void verifySignature(String data, String signature, String publickey) throws Exception {
		// Creating a Signature object
		Signature sign   = Signature.getInstance("SHA256withDSA");

		PublicKey pubKey = KeyFactory.getInstance("DSA")
				.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publickey)));
		sign.initVerify(pubKey);
		System.out.println(pubKey);
		byte[] dataByte = data.getBytes(StandardCharsets.UTF_8);
		sign.update(dataByte);

		// Verifying the signature
		byte[] signatureByte = Base64.getDecoder().decode(signature);
		System.out.println(signatureByte);
		boolean bool = sign.verify(signatureByte);

		if (bool) {
			System.out.println("Signature verified");
		} else {
			System.out.println("Signature failed");
		}
	}
}
