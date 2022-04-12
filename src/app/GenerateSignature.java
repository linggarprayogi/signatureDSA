package app;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;

public class GenerateSignature {

	public static void main(String[] args) throws Exception {
		// Creating KeyPair generator object
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");

		// Initializing the key pair generator
		keyPairGen.initialize(1024);

		// Generate the pair of keys
		KeyPair    pair      = keyPairGen.generateKeyPair();

		// Getting the privatekey from the key pair
		PrivateKey privKey   = pair.getPrivate();

		/* Get the public key from the encoded byte array */
		PublicKey  pubKey    = KeyFactory.getInstance("DSA")
				.generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));
		String     pubKeyStr = Base64.getEncoder().encodeToString(pubKey.getEncoded());

		// Creating a Signature object
		Signature  sign      = Signature.getInstance("SHA256withDSA");

		// Initializing the signature
		sign.initSign(privKey);

//		Date     currentDate = new Date();
		Calendar calendar = Calendar.getInstance(); // gets a calendar using the default time zone and locale.
		calendar.add(Calendar.SECOND, 60);
		Long   unixTime = calendar.getTimeInMillis();
		String dataStr  = "INV001|" + unixTime + "|";

		byte[] data     = dataStr.getBytes(StandardCharsets.UTF_8);

		// Adding data to the signature
		sign.update(data);

		// Calculating the signature
		byte[] signature = sign.sign();

		System.out.println("Signature : " + Base64.getEncoder().encodeToString(signature) + " " + signature);
		System.out.println("Public key : " + pubKeyStr);
		System.out.println("Private key : " + privKey);
		System.out.println(
				"Output : " + new String(data, StandardCharsets.UTF_8) + Base64.getEncoder().encodeToString(signature));
	}
}
