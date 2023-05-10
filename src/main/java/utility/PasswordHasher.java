package utility;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordHasher {
    public static String hashPassword(String password, String salt) {
        String saltedPassword = password + salt;
        byte[] hash = {};
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            hash = messageDigest.digest(saltedPassword.getBytes());
        } catch (NoSuchAlgorithmException ignored) {
        }
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) stringBuilder.append('0');
            stringBuilder.append(hex);
        }
        return stringBuilder.toString();
    }
}