import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static String CIPHER = "/CBC/PKCS5PADDING";
    private static int COUNT = 1000;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        if ((args.length != 6 && args.length != 4 && args.length != 2)
                && (!args[0].equals("enc") && !args[0].equals("dec") && args[0].equals("info"))) {
            System.out.println("Wrong arguments given");
            return;
        }

        String state = args[0];

        if (state.equals("enc")) {
            CIPHER = args[1] + CIPHER;
            int keyLength = Integer.parseInt(args[2]);
            String cipher = args[1];
            String password = args[3];
            String inputFile = args[4];
            String outputFile = args[5];
            System.out.println(CIPHER);
            encryption(cipher, keyLength, password, inputFile, outputFile);
        } else if (state.equals("dec")) {
            String password = args[1];
            String inputFile = args[2];
            String outputFile = args[3];
            decryption(password, inputFile, outputFile);
        } else if (state.equals("info")) {
            System.out.println(getMetaData(args[1]));
        }
    }

    public static void encryption(String cipher, Integer keyLength, String password, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, InvalidKeySpecException {
        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();

        PBEKeySpec pbeKeySpec;
        PBEParameterSpec pbeParamSpec;
        SecretKeyFactory keyFac;

        byte[] salt = new byte[16];
        sr.nextBytes(salt); // 16 bytes salt
        int ivLength = cipher.equals("AES") ? 16 : 8;
        byte[] iv = new byte[ivLength];
        sr.nextBytes(iv); // 16 bytes salt
        IvParameterSpec ivParamSpec = new IvParameterSpec(iv);

        // Iteration count
        int count = 1000;

        // Create PBE parameter set
        pbeParamSpec = new PBEParameterSpec(salt, count, ivParamSpec);
        char[] passwordChar = password.toCharArray();
        //pbeKeySpec = new PBEKeySpec(passwordChar, salt, count, keyLength);
       // keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
        //SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, keyLength);
        SecretKey pbeKey = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), cipher);


        // Create PBE Cipher
        Cipher pbeCipher = Cipher.getInstance(CIPHER);
        // Initialize PBE Cipher with key and parameters
        pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, ivParamSpec);

        System.out.println("Random key=" + Base64.getEncoder().encodeToString(pbeKey.toString().getBytes()));
        System.out.println("initVector=" + Base64.getEncoder().encodeToString(salt));

        //Look for files here
        final Path tempDir = Paths.get("").toAbsolutePath();

        final Path encryptedPath = tempDir.resolve(outputFile);
        final Path inputPath = tempDir.resolve(inputFile);

        try (InputStream fin = Files.newInputStream(inputPath);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, pbeCipher) {
             }) {
            final byte[] bytes = new byte[1024];
            fout.write(cipher.getBytes().length);
            fout.write(cipher.getBytes());
            fout.write(keyLength.toString().getBytes().length);
            fout.write(keyLength.toString().getBytes());
            fout.write(salt);
            fout.write(iv);
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        LOG.info("Encryption finished, saved at " + encryptedPath);
        writeMetaData(keyLength, outputFile);

    }

    public static void decryption(String base64SecretKey, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, InvalidKeySpecException {

        String info = getMetaData(inputFile);
        String[] data = info.split(" ");
        CIPHER = data[0] + CIPHER;
        int keyLength = Integer.parseInt(data[1]);

        PBEKeySpec pbeKeySpec;
        PBEParameterSpec pbeParamSpec;
        SecretKeyFactory keyFac;

        // Iteration count
        int count = 1000;

        // Create PBE parameter set
        char[] passwordChar = base64SecretKey.toCharArray();


        //Look for files here
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(inputFile);

        final Path decryptedPath = tempDir.resolve(outputFile);
        InputStream encryptedData = Files.newInputStream(encryptedPath);


        try {
            byte[] cipherLength = encryptedData.readNBytes(1);
            byte[] cipher = encryptedData.readNBytes(cipherLength[0]);
            String s = new String(cipher, StandardCharsets.UTF_8);

            byte[] keyLen = encryptedData.readNBytes(1);
            byte[] key = encryptedData.readNBytes(keyLen[0]);
            String ss = new String(key, StandardCharsets.UTF_8);
            byte[] salt = encryptedData.readNBytes(16);
            int ivLength = cipher.equals("AES") ? 16 : 8;
            byte[] initVector = encryptedData.readNBytes(ivLength);



            pbeKeySpec = new PBEKeySpec(passwordChar, salt, count, keyLength);
            keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(passwordChar, salt, 1000, keyLength);
            SecretKey pbeKey = new SecretKeySpec(factory.generateSecret(spec)
                    .getEncoded(), s);

            // Create PBE Cipher
            Cipher pbeCipher = Cipher.getInstance(CIPHER);

            IvParameterSpec ivParamSpec = new IvParameterSpec(initVector);

            System.out.println("initVector=" + Base64.getEncoder().encodeToString(initVector));
            System.out.println("password=" + Base64.getEncoder().encodeToString(pbeKey.toString().getBytes()));

            pbeParamSpec = new PBEParameterSpec(salt, count, ivParamSpec);
            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, ivParamSpec);


            CipherInputStream decryptStream = new CipherInputStream(encryptedData, pbeCipher);
            OutputStream decryptedOut = Files.newOutputStream(decryptedPath);
            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        } finally {
            encryptedData.close();
        }

        LOG.info("Decryption complete, open " + decryptedPath);
    }

    public static String getMetaData(String filename) throws IOException {
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(filename);
        InputStream encryptedData = Files.newInputStream(encryptedPath);
        byte[] cipherLength = encryptedData.readNBytes(1);
        byte[] cipher = encryptedData.readNBytes(cipherLength[0]);
        String s = new String(cipher, StandardCharsets.UTF_8);

        byte[] keyLen = encryptedData.readNBytes(1);
        byte[] key = encryptedData.readNBytes(keyLen[0]);
        String ss = new String(key, StandardCharsets.UTF_8);

        return (s + " " + ss);
    }

    public static void writeMetaData(int keylength, String filename) throws IOException {

    }
}