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
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        if (args.length != 4 || (!args[0].equals("enc") && !args[0].equals("dec"))) {
            System.out.println("Wrong arguments given");
            return;
        }

        String state = args[0];

        if (state.equals("enc")) {
            String base64SecretKey = args[1];
            String inputFile = args[2];
            String outputFile = args[3];
            encryption(base64SecretKey, inputFile, outputFile);


        } else if (state.equals("dec")) {
            String base64SecretKey = args[1];
            String inputFile = args[2];
            String outputFile = args[3];
            decryption(base64SecretKey, inputFile, outputFile);
        }
    }

    public static void encryption(String base64SecretKey, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();

        byte[] key = Base64.getDecoder().decode(base64SecretKey);
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV

        System.out.println("Random key=" + Base64.getEncoder().encodeToString(key));
        System.out.println("initVector=" + Base64.getEncoder().encodeToString(initVector));
        System.out.println(initVector);

        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);

        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        //Look for files here
        final Path tempDir = Paths.get("").toAbsolutePath();

        final Path encryptedPath = tempDir.resolve(outputFile);
        final Path inputPath = tempDir.resolve(inputFile);

        try (InputStream fin = Files.newInputStream(inputPath);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            final byte[] bytes = new byte[1024];
            fout.write(initVector);
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        LOG.info("Encryption finished, saved at " + encryptedPath);

    }

    public static void decryption(String base64SecretKey, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        byte[] key = Base64.getDecoder().decode(base64SecretKey);

        //Look for files here
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(inputFile);

        final Path decryptedPath = tempDir.resolve(outputFile);
        InputStream encryptedData = Files.newInputStream(encryptedPath);


        try {
            byte[] initVector = encryptedData.readNBytes(16);

            System.out.println("initVector=" + Base64.getEncoder().encodeToString(initVector));

            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
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