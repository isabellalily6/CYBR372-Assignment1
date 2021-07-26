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
 *
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        if((args.length != 3 && args.length != 5) || (!args[0].equals("enc") && !args[0].equals("dec"))){
            System.out.println("Wrong arguments given 1");
            return;
        }
        if(((args.length != 3 && args[0].equals("enc")) || (args.length != 5 && args[0].equals("dec")))){
            System.out.println("Wrong arguments given 2");
            return;
        }
        String state = args[0];

        if(state.equals("enc")){
            String inputFile = args[1];
            String outputFile = args[2];
            encryption(inputFile, outputFile);


        } else if(state.equals("dec")){
            String base64SecretKey = args[1];
            String base64IV = args[2];
            String inputFile = args[3];
            String outputFile = args[4];
            decryption(base64SecretKey, base64IV, inputFile, outputFile);
        }
    }

    public static void encryption(String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV

        System.out.println("Random key=" + Base64.getEncoder().encodeToString(key));
        System.out.println("initVector=" + Base64.getEncoder().encodeToString(initVector));

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
            for(int length=fin.read(bytes); length!=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        LOG.info("Encryption finished, saved at " + encryptedPath);

    }

    public static void decryption(String base64SecretKey, String base64IV, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        byte[] key = Base64.getDecoder().decode(base64SecretKey);
        byte[] initVector = Base64.getDecoder().decode(base64IV);

        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);

        //Look for files here
        final Path tempDir = Paths.get("").toAbsolutePath();

        final Path encryptedPath = tempDir.resolve(inputFile);

        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        final Path decryptedPath = tempDir.resolve(outputFile);
        try(InputStream encryptedData = Files.newInputStream(encryptedPath);
            CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = Files.newOutputStream(decryptedPath)){
            final byte[] bytes = new byte[1024];
            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }

        LOG.info("Decryption complete, open " + decryptedPath);
    }
}