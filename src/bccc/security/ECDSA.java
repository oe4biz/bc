package bccc.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

//import javax.xml.bind.DatatypeConverter;

public class ECDSA {

	/**
	 * 楕円曲線DSA 署名検証サンプル
	 */
	public static void main(String[] args) throws Exception {
		/*
		 *  楕円曲線暗号 鍵ペア生成
		 */
		// 鍵ペア生成器
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC"); // Elliptic Curve
		// 乱数生成器
		SecureRandom randomGen = SecureRandom.getInstance("SHA1PRNG");
		// 鍵サイズと乱数生成器を指定して鍵ペア生成器を初期化
		int keySize = 256;
		keyGen.initialize(keySize, randomGen);

		// 鍵ペア生成
		KeyPair keyPair = keyGen.generateKeyPair();
		// 秘密鍵
		PrivateKey privateKey = keyPair.getPrivate();
		// 公開鍵
		PublicKey publicKey = keyPair.getPublic();

		System.out.println();
		//System.out.println("privateKey=\t" + DatatypeConverter.printHexBinary(privateKey.getEncoded()));
		System.out.println("privateKey=\t" + Security.toStringByHash(privateKey.getEncoded()));
		System.out.println("publicKey=\t" + Security.toStringByHash(publicKey.getEncoded()));

		/*
		 * 署名生成
		 */
		String originalText = "This is string to sign";

		// 署名生成アルゴリズムを指定する
		Signature dsa = Signature.getInstance("SHA256withECDSA");
		// 初期化
		dsa.initSign(privateKey);
		// 署名生成
		dsa.update(originalText.getBytes("US-ASCII"));
		// 生成した署名を取り出す
		byte[] signature = dsa.sign();
		System.out.println("Signature: " + Security.toStringByHash(signature));

		/*
		 * 署名検証
		 */
		// 初期化
		dsa.initVerify(publicKey);
		// 署名検証する対象をセットする
		dsa.update(originalText.getBytes("US-ASCII"));
		// 署名検証
		boolean verifyResult = dsa.verify(signature);
		System.out.println("Verify: " + verifyResult);
	}
}
