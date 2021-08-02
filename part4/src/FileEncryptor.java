import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
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

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        if ((args.length != 6 && args.length != 4 && args.length != 2) || (!args[0].equals("enc") && !args[0].equals("dec") && args[0].equals("info"))) {
            System.out.println("Wrong arguments given");
            return;
        }

        String state = args[0];

        if (state.equals("enc")) {
            String password = args[1];
            String inputFile = args[2];
            String outputFile = args[3];
            encryption(password, inputFile, outputFile);


        } else if (state.equals("dec")) {
            String password = args[1];
            String inputFile = args[2];
            String outputFile = args[3];
            decryption(password, inputFile, outputFile);
        } else if (state.equals("info")) {
            
        }
    }

    public static void encryption(String password, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, InvalidKeySpecException {
        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();

        PBEKeySpec pbeKeySpec;
        PBEParameterSpec pbeParamSpec;
        SecretKeyFactory keyFac;

        byte[] salt = new byte[16];
        sr.nextBytes(salt); // 16 bytes salt
        byte[] iv = new byte[16];
        sr.nextBytes(iv); // 16 bytes salt
        IvParameterSpec ivParamSpec = new IvParameterSpec(iv);

        // Iteration count
        int count = 1000;

        // Create PBE parameter set
        pbeParamSpec = new PBEParameterSpec(salt, count, ivParamSpec);
        char[] passwordChar = password.toCharArray();
        pbeKeySpec = new PBEKeySpec(passwordChar);
        keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

        // Create PBE Cipher
        Cipher pbeCipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_256");
        System.out.println(pbeParamSpec.toString());

        // Initialize PBE Cipher with key and parameters
        pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

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
            fout.write(salt);
            fout.write(iv);
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        LOG.info("Encryption finished, saved at " + encryptedPath);

    }

    public static void decryption(String base64SecretKey, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, InvalidKeySpecException {

        PBEKeySpec pbeKeySpec;
        PBEParameterSpec pbeParamSpec;
        SecretKeyFactory keyFac;

        // Iteration count
        int count = 1000;

        // Create PBE parameter set
        char[] passwordChar = base64SecretKey.toCharArray();
        pbeKeySpec = new PBEKeySpec(passwordChar);
        keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

        // Create PBE Cipher
        Cipher pbeCipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_256");


        //Look for files here
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(inputFile);

        final Path decryptedPath = tempDir.resolve(outputFile);
        InputStream encryptedData = Files.newInputStream(encryptedPath);


        try {
            byte[] salt = encryptedData.readNBytes(16);
            byte[] initVector = encryptedData.readNBytes(16);

            IvParameterSpec ivParamSpec = new IvParameterSpec(initVector);

            System.out.println("initVector=" + Base64.getEncoder().encodeToString(initVector));
            System.out.println("password=" + Base64.getEncoder().encodeToString(pbeKey.toString().getBytes()));

            pbeParamSpec = new PBEParameterSpec(salt, count, ivParamSpec);
            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);


            System.out.println(pbeParamSpec.toString());
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
}