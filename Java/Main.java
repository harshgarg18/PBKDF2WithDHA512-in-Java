import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {

    public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String originalPassword = "myPassword@12";
        String encryptedPassword = PBKDF2WithHmacSHA512.hash(originalPassword);
        System.out.println("Encrypted Password: " + encryptedPassword);
        String attemptedPassword1 = "myPassword@12";
        boolean matched1 = PBKDF2WithHmacSHA512.authenticate(attemptedPassword1, encryptedPassword);
        System.out.println("\nPassword 1 matched: " + matched1);
        String attemptedPassword2 = "mypassword@12";
        boolean matched2 = PBKDF2WithHmacSHA512.authenticate(attemptedPassword2, encryptedPassword);
        System.out.println("\nPassword 1 matched: " + matched2);
    }

}