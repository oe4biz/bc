package bccc.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class Base58Check {

	public static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	private static final BigInteger ALPHABET_SIZE = BigInteger.valueOf(ALPHABET.length());

	/**
	 * Base58に変換(checksum有)。
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String bytesToBase58Check(byte[] data) throws NoSuchAlgorithmException {
		return rawBytesToBase58(addCheckHash(data));
	}

	/**
	 * Base58に変換(checksum無)。
	 * @param data
	 * @return
	 */
	public static String bytesToBase58(byte[] data) {
		return rawBytesToBase58(data);
	}

	/**
	 * Base58Check。
	 * @param data
	 * @return
	 */
	static String rawBytesToBase58(byte[] data) {
		// Convert to base-58 string
		StringBuilder sb = new StringBuilder();
		BigInteger num = new BigInteger(1, data);
		while (num.signum() != 0) {
			BigInteger[] quotrem = num.divideAndRemainder(ALPHABET_SIZE);
			sb.append(ALPHABET.charAt(quotrem[1].intValue()));
			num = quotrem[0];
		}

		// Add '1' characters for leading 0-value bytes
		for (int i = 0; i < data.length && data[i] == 0; i++)
			sb.append(ALPHABET.charAt(0));
		return sb.reverse().toString();
	}


	/**
	 * checksum付与。
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	static byte[] addCheckHash(byte[] data) throws NoSuchAlgorithmException {
		try {
			byte[] hash = Arrays.copyOf(Security.getHashByteDoubleSha256(data), 4);
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			buf.write(data);
			buf.write(hash);
			return buf.toByteArray();
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}


	/**
	 * base58からbytesに変換(checksum含まない)
	 * @param s
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] base58ToBytes(String s) throws NoSuchAlgorithmException {
		byte[] concat = base58ToRawBytes(s);
		byte[] data = Arrays.copyOf(concat, concat.length - 4);
		byte[] hash = Arrays.copyOfRange(concat, concat.length - 4, concat.length);
		byte[] rehash = Arrays.copyOf(Security.getHashByteDoubleSha256(data), 4);
		if (!Arrays.equals(rehash, hash))
			throw new IllegalArgumentException("Checksum mismatch");
		return data;
	}


	/**
	 * base58からbytesに変換(checksum含む)
	 * @param s
	 * @return
	 */
	static byte[] base58ToRawBytes(String s) {
		BigInteger num = BigInteger.ZERO;
		for (int i = 0; i < s.length(); i++) {
			num = num.multiply(ALPHABET_SIZE);
			int digit = ALPHABET.indexOf(s.charAt(i));
			if (digit == -1)
				throw new IllegalArgumentException("Invalid character for Base58Check");
			num = num.add(BigInteger.valueOf(digit));
		}

		byte[] b = num.toByteArray();
		if (b[0] == 0)
			b = Arrays.copyOfRange(b, 1, b.length);

		try {
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			for (int i = 0; i < s.length() && s.charAt(i) == ALPHABET.charAt(0); i++)
				buf.write(0);
			buf.write(b);
			return buf.toByteArray();
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	private Base58Check() {}

}
