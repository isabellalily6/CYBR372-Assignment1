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
 * @author Isabella Tomaz-Ketley
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    /**
     * Main method which checks whether the arguments passed in are correct
     * and if so calls, the corresponding methods.
     *
     * @param args the terminal arguments
     */
    public static void main(String[] args) {
        // Check whether the number of arguments given are valid
        if ((args.length != 3 && args.length != 5)) {
            System.out.println("Wrong number of arguments given");
            return;
        }
        // Check whether the state and correct number of arguments are given, depending on the action
        if (((args.length == 3 && !args[0].equals("enc")) || (args.length == 5 && !args[0].equals("dec")))) {
            System.out.println("Wrong arguments given");
            return;
        }

        String state = args[0];

        try {
            if (state.equals("enc")) {
                // if the state is enc, set the cipher and encrypt the file
                String inputFile = args[1];
                String outputFile = args[2];
                encryption(inputFile, outputFile);
            } else if (state.equals("dec")) {
                // if the state is dec, decrypt the file
                String base64SecretKey = args[1];
                String base64IV = args[2];
                String inputFile = args[3];
                String outputFile = args[4];
                decryption(base64SecretKey, base64IV, inputFile, outputFile);
            }
        // These catch statements make the code more secure as they don't disclose important information
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, an error occured reading a file");
        } catch (NoSuchPaddingException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the padding scheme is incorrect");
        } catch (NoSuchAlgorithmException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the encryption algorithm is incorrect");
        } catch (InvalidKeyException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the encryption key is invalid");
        } catch (InvalidAlgorithmParameterException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the algorithm is invalid");
        } catch (Exception e) {
            LOG.log(Level.INFO, "Unable to decrypt, " + e.getMessage());
        }
    }

    /**
     * Encrypts a given file, to an output file.
     *
     * @param inputFile  the input file to encrypt
     * @param outputFile the output file of the encrypted information
     */
    public static void encryption(String inputFile, String outputFile) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        SecureRandom sr = new SecureRandom();

        // create the 16 byte (128 bit) key
        // this makes the code secure as the key is randomly generated using SecureRandom
        byte[] key = new byte[16];
        sr.nextBytes(key);

        // create the 16 byte IV
        // this makes the code secure as the IV is randomly generated using SecureRandom
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector);
        IvParameterSpec iv = new IvParameterSpec(initVector);

        // Create and initialise the cipher using the key and IV
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        // Determine where to find the files and find them
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(outputFile);
        final Path inputPath = tempDir.resolve(inputFile);

        // open each of the files
        // this makes the code secure as a CipherOutputStream is used
        try (InputStream fin = Files.newInputStream(inputPath);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            final byte[] bytes = new byte[1024];
            // encrypt and write the encrypted data to the output file
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
            // print out the base64 encoded key and IV
            System.out.println("Secret key= " + Base64.getEncoder().encodeToString(key));
            System.out.println("initVector= " + Base64.getEncoder().encodeToString(initVector));

            LOG.info("Encryption finished, saved at " + encryptedPath);
        }
    }

    /**
     * Decrypts a given file, to an output file using the information passed as parameters.
     *
     * @param base64SecretKey the password used to encrypt the file, encoded in base64
     * @param base64IV        the IV used to encrypt the file, encoded in base64
     * @param inputFile       the input file to encrypt
     * @param outputFile      the output file of the encrypted information
     */
    public static void decryption(String base64SecretKey, String base64IV, String inputFile, String outputFile) throws Exception {
        // Create parameters to store the key and initVector
        byte[] key;
        byte[] initVector;

        // Retrieve the key and IV by decoding the given parameters
        try {
            key = Base64.getDecoder().decode(base64SecretKey);
            initVector = Base64.getDecoder().decode(base64IV);
        } catch(Exception e){
            throw new Exception("incorrect base64 parameters entered");
        }

        // Create the IV
        IvParameterSpec iv = new IvParameterSpec(initVector);

        // Create and initialise the cipher using the key and IV
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        // Determine where to find the files and find them
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(inputFile);
        final Path decryptedPath = tempDir.resolve(outputFile);

        // open each of the files
        // this makes the code secure as a CipherInputStream is used
        try (InputStream encryptedData = Files.newInputStream(encryptedPath);
             CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
             OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
            final byte[] bytes = new byte[1024];
            // decrypt and write the decrypted data to the output file
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
            LOG.info("Decryption complete, open " + decryptedPath);
        }
    }
}