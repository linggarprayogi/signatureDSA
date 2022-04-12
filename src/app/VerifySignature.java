package app;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class VerifySignature {

	public static void main(String[] args) throws Exception {
		verifySignature("INV001|1649737886047|", "MCwCFCY5vxMRIRDQbQ07qUrbAt5KlT4CAhRExtV9QjKps65bqORU4VdDWv6zWA==",
				"MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAECwvalyMyj0NkIf/IXkfcxCeggRdNOpOFFX7NmDEu/BcQ3Cfy45srItHCm+O44iJcSQnCrvrA2bASMd0TSKZbFSFgO5gLczeUKUWha5TT7DtCXxBy/fNznDe/con7J28y3BDvWiuYRf+7e+LbQxFdoLV55f5Hx5ez9xDPQQMdRs=");
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
		boolean bool        = sign.verify(signatureByte);

		Date    currentDate = new Date();
		if (currentDate.compareTo(new Date(1649737886047l)) > 0) {
			System.out.println("Expire Date");
		}

		if (bool) {
			System.out.println("Signature verified");
		} else {
			System.out.println("Signature failed");
		}
	}
}
