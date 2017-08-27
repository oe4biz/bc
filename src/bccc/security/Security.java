package bccc.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

public class Security {

	static public byte[] getHashByteSha1(String d) throws NoSuchAlgorithmException {
		return getHashByte(d, "SHA-1");
	}

	static public String getHashStringSha1(String d) throws NoSuchAlgorithmException {
		return toStringByHash(getHashByteSha1(d));
	}

	static public byte[] getHashByteSha256(String d) throws NoSuchAlgorithmException {
		return getHashByte(d, "SHA-256");
	}

	static public byte[] getHashByteSha256(byte[] d) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(d);
	}

	static public String getHashStringSha256(String d) throws NoSuchAlgorithmException {
		return toStringByHash(getHashByteSha256(d));
	}

	static public byte[] getHashByteSha512(String d) throws NoSuchAlgorithmException {
		return getHashByte(d, "SHA-512");
	}

	static public String getHashStringSha512(String d) throws NoSuchAlgorithmException {
		return toStringByHash(getHashByteSha512(d));
	}

	static public byte[] getHashByteDoubleSha256(String d) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(getHashByteSha256(d));
	}

	static public byte[] getHashByteDoubleSha256(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(getHashByteSha256(data));
	}

	static public String getHashStringDoubleSha256(String d) throws NoSuchAlgorithmException {
		return toStringByHash(getHashByteDoubleSha256(d));
	}

	static public String getHashString(String d, String algo) throws NoSuchAlgorithmException {
		return toStringByHash(getHashByte(d, algo));
	}

	static public byte[] getHashByte(String d, String algo) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algo);
		return md.digest(d.getBytes());
	}

	static public String getHashStringRipemd160(String d) {
		RIPEMD160Digest sd = new RIPEMD160Digest();
		byte[] output = new byte[sd.getDigestSize()];
		sd.update(d.getBytes(), 0, d.getBytes().length);
		sd.doFinal(output, 0);
		return toStringByHash(output);
	}

	static public String getHashStringRipemd160Sha256(String d) throws NoSuchAlgorithmException {
		byte[] sha256 = getHashByte(d, "SHA-256");

		RIPEMD160Digest rd = new RIPEMD160Digest();
		byte[] output = new byte[rd.getDigestSize()];
		rd.update(sha256, 0, sha256.length);
		rd.doFinal(output, 0);
		return toStringByHash(output);
	}

	/**
	 * ハッシュを元に16進数のハッシュ文字列を返します。
	 * @param hash ハッシュ
	 * @return ハッシュ文字列
	 */
	static public String toStringByHash(final byte[] hash) {
		StringBuilder sb = new StringBuilder();
		for (byte b : hash) {
			String val = Integer.toHexString(b & 0xff);
			if (val.length() == 1) {
				sb.append('0').append(val);
			} else {
				sb.append(val);
			}
		}
		return sb.toString();
	}

}