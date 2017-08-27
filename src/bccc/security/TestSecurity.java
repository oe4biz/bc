package bccc.security;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

public class TestSecurity {

	public static void main(String[] args) {

		String d = "example data to be hashed";
		String res = null;

		try {
			res = Security.getHashStringSha1(d);
			System.out.println("Sha1 =\t" + res);

			res = Security.getHashStringSha256(d);
			System.out.println("Sha256 =\t" + res);

			res = Security.getHashStringSha512(d);
			System.out.println("Sha512 =\t" + res);

			res = Security.getHashStringDoubleSha256(d);
			System.out.println("DoubleSha256 =\t" + res);

			res = Security.getHashStringRipemd160(d);
			System.out.println("RIPEMD160 =\t" + res);

			res = Security.getHashStringRipemd160Sha256(d);
			System.out.println("RIPEMD160SHA256 =\t" + res);

			d = "example data";
			String b58c = Base58Check.bytesToBase58Check(d.getBytes());
			System.out.println("Base58check=\t" + b58c);

			byte[] decode = Base58Check.base58ToRawBytes(b58c);
			byte[] data = Arrays.copyOf(decode, decode.length - 4);
			byte[] hash = Arrays.copyOfRange(decode, decode.length - 4, decode.length);
			byte[] rehash = Arrays.copyOf(Security.getHashByteDoubleSha256(data), 4);
			System.out.println(Security.toStringByHash(decode));
			System.out.println(Security.toStringByHash(data));
			System.out.println(Security.toStringByHash(hash));
			System.out.println(Security.toStringByHash(rehash));
			System.out.println("decode2=\t" + Security.toStringByHash(Base58Check.base58ToBytes(b58c)));
			System.out.println("decode2=\t" + DatatypeConverter.printHexBinary(Base58Check.base58ToBytes(b58c)));

		} catch (NoSuchAlgorithmException e) {
		}
	}

}
