import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * <p>
 * This class is used for encrypting passwords using the PBKDF2WithHmacSHA512
 * algorithm. Passwords are salted using SHA1PRNG.
 * </p>
 *
 * <a href=
 * "http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf"
 * >Specification referenced</a>.<br>
 * <a href="http://tools.ietf.org/search/rfc2898">RFC2898 - Password-Based
 * Cryptography Specification</a>
 *
 */
public final class PBKDF2WithHmacSHA512 {

    /**
     * This is the algorithm this service uses.
     */
    private static final String ALGORITHM = PBKDF2WithHmacSHA512.class.getSimpleName();

    /**
     * The amount of computation needed to derive a key from the password. Note:
     * The bigger the number the longer it'll take to a generate key. Note: When
     * user based performance is not an issue, a value of 10,000,000 is
     * recommended otherwise a minimum of 1000 recommended.
     */
    private static final int ITERATION_COUNT = 1000;

    /**
     * The length of the derived key.
     */
    private static final int KEY_LENGTH = 512;

    /**
     * Private constructor to stop the class from being instantiated.
     *
     * @throws AssertionError If the class tried to be instantiated.
     */
    private PBKDF2WithHmacSHA512() {
        throw new AssertionError();
    }

    /**
     * This method returns an encrypted byte[] of the password.
     *
     * @param password The password to encrypt.
     * @param salt The random data used for the hashing function.
     * @return The encrypted password as a byte[].
     * @throws NoSuchAlgorithmException If the cryptographic algorithm is
     * unavailable.
     * @throws InvalidKeySpecException If the derived key cannot be produced.
     */
    private static byte[] hash(final String password, final byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        final SecretKeyFactory secretKeyfactory = SecretKeyFactory.getInstance(ALGORITHM);
        return secretKeyfactory.generateSecret(keySpec).getEncoded();
    }

    /**
     * This method returns an encrypted String of the password.
     *
     * @param password The password to encrypt.
     * @return The encrypted password as String in format "salt:hash"
     * @throws NoSuchAlgorithmException It is thrown when the cryptographic algorithm is not available in the environment.
     * @throws InvalidKeySpecException This is the exception for invalid key specifications.
     */
    public static String hash(final String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        final byte salt[] = getSalt();
        final byte hash[] = hash(password, salt);
        return toHex(salt) + ":" + toHex(hash);
    }

    /**
     * Generates a random salt used for password matching.
     *
     * @return A randomly produced byte[].
     *
     * @throws NoSuchAlgorithmException If SHA1PRNG does not exist on the
     * system.
     */
    private static byte[] getSalt() throws NoSuchAlgorithmException {
        final byte[] salt = new byte[16];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(salt);
        return salt;
    }

    private static String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    private static byte[] fromHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    /**
     * Checks the attemptedPassword against the encryptedPassword using the
     * random salt.
     *
     * @param attemptedPassword The password entered by the user.
     * @param encryptedPassword The hashed password stored on the database.
     * @return If the attempted password matched the hashed password.
     * @throws NoSuchAlgorithmException It is thrown when the cryptographic algorithm is not available in the environment.
     * @throws InvalidKeySpecException This is the exception for invalid key specifications.
     */
    public static boolean authenticate(final String attemptedPassword, final String encryptedPassword)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        String parts[] = encryptedPassword.split(":");
        byte salt[] = fromHex(parts[0]);
        byte storedHash[] = fromHex(parts[1]);
        byte testHash[] = hash(attemptedPassword, salt);

        return Arrays.equals(storedHash, testHash);
    }
}
