package utility;

import java.util.Random;

public class RandomTextGenerator {
    private static final String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    private static final String colorCharacters = "0123456789ABCDEF";
    private static final Random random = new Random();

    public static String generate(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(characters.length());
            sb.append(characters.charAt(randomIndex));
        }
        return sb.toString();
    }
    public static String generateColor(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(colorCharacters.length());
            sb.append(colorCharacters.charAt(randomIndex));
        }
        return sb.toString();
    }
}