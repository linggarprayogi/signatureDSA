package app;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class VerifySignature {

	public static void main(String[] args) throws Exception {
		File   publicKeyFile  = new File("publicDsa.key");
		byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

		verifySignature("INV001|1649751179779|",
				"MD0CHEWIU/2OlWnuNJeYZU/1JZP8Bdt7M4O1RWKHYdoCHQC2kTn9upAiwFSzsZ9p+jhTvfrtxm6dPwHJVZyM", publicKeyBytes);
	}

	public static void verifySignature(String data, String signature, byte[] publickey) throws Exception {
		// Creating a Signature object
		Signature sign   = Signature.getInstance("SHA256withDSA");

		PublicKey pubKey = KeyFactory.getInstance("DSA").generatePublic(new X509EncodedKeySpec(publickey));
		sign.initVerify(pubKey);
		System.out.println(pubKey);
		byte[] dataByte = data.getBytes(StandardCharsets.UTF_8);
		sign.update(dataByte);

		// Verifying the signature
		byte[] signatureByte = Base64.getDecoder().decode(signature);
		System.out.println(signatureByte);
		boolean bool        = sign.verify(signatureByte);

		Date    currentDate = new Date();
		if (currentDate.compareTo(new Date(1649751179779l)) > 0) {
			System.out.println("Expire Date");
		}

		if (bool) {
			System.out.println("Signature verified");
		} else {
			System.out.println("Signature failed");
		}
	}
}
