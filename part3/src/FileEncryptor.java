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
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Isabella Tomaz-Ketley
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int KEYLENGTH = 128;
    // This count makes the code more secure as it adheres to the NIST specifications
    private static final int COUNT = 400000;


    /**
     * Main method which checks whether the arguments passed in are correct
     * and if so calls, the corresponding methods.
     *
     * @param args the terminal arguments
     */
    public static void main(String[] args) {
        // Check whether state and the correct number of arguments are given
        if (args.length != 4 || (!args[0].equals("enc") && !args[0].equals("dec"))) {
            System.out.println("Wrong arguments given");
            return;
        }

        String state = args[0];

        try {
            if (state.equals("enc")) {
                // if the state is enc, set the cipher and encrypt the file
                String password = args[1];
                String inputFile = args[2];
                String outputFile = args[3];
                encryption(password, inputFile, outputFile);
            } else if (state.equals("dec")) {
                // if the state is dec, decrypt the file
                String password = args[1];
                String inputFile = args[2];
                String outputFile = args[3];
                decryption(password, inputFile, outputFile);
            }
        // These catch statements make the code more secure as they don't disclose important information
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, an error occurred reading or writing to a file");
        } catch (NoSuchPaddingException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the padding scheme is incorrect");
        } catch (NoSuchAlgorithmException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the encryption algorithm is incorrect");
        } catch (InvalidKeyException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the encryption key is invalid");
        } catch (InvalidAlgorithmParameterException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the algorithm is invalid");
        }
    }

    /**
     * Encrypts a given file, to an output file using the information passed as parameters.
     *
     * @param password   the password used to encrypt the file
     * @param inputFile  the input file to encrypt
     * @param outputFile the output file of the encrypted information
     */
    public static void encryption(String password, String inputFile, String outputFile) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        SecureRandom sr = new SecureRandom();

        // create the 16 byte salt
        // this makes the code secure as the salt is randomly generated using SecureRandom
        // this salt makes the code more secure as it is 16 bytes which adheres to the NIST specifications
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        // create the 16 byte iv
        // this makes the code secure as the IV is randomly generated using SecureRandom
        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        IvParameterSpec ivParamSpec = new IvParameterSpec(iv);

        // Determine where to find the files and find them
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(outputFile);
        final Path inputPath = tempDir.resolve(inputFile);

        // try and open the input and output file
        try (InputStream fin = Files.newInputStream(inputPath);
             OutputStream fout = Files.newOutputStream(encryptedPath)) {

            // Generate the secret key
            SecretKey key = generateSecretKey(password, salt);

            // Create and initialize the cipher with key and parameters
            Cipher PCipher = Cipher.getInstance(CIPHER);
            PCipher.init(Cipher.ENCRYPT_MODE, key, ivParamSpec);

            // write the salt and IV to the output file
            fout.write(salt);
            fout.write(iv);

            // encrypt and write the encrypted data to the output file
            // this makes the code secure as a CipherOutputStream is used
            try (CipherOutputStream cipherOut = new CipherOutputStream(fout, PCipher)) {
                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }
            }
            System.out.println("password= " + Base64.getEncoder().encodeToString(key.getEncoded()));
            LOG.info("Encryption finished, saved at " + encryptedPath);
        }
    }

    /**
     * Decrypts a given file, to an output file using the information passed as parameters.
     *
     * @param password   the password used to encrypt the file
     * @param inputFile  the input file to encrypt
     * @param outputFile the output file of the encrypted information
     */
    public static void decryption(String password, String inputFile, String outputFile) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        // Determine where to find the files and find them
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(inputFile);
        final Path decryptedPath = tempDir.resolve(outputFile);

        // try and open the input and output file
        try (InputStream encryptedData = Files.newInputStream(encryptedPath);
             OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {

            // Retrieve the salt and IV from the input file
            byte[] salt = encryptedData.readNBytes(16);
            byte[] initVector = encryptedData.readNBytes(16);
            IvParameterSpec ivParamSpec = new IvParameterSpec(initVector);

            // Generate the secret key
            SecretKey key = generateSecretKey(password, salt);

            // Create and initialize the cipher with key and parameters
            Cipher pCipher = Cipher.getInstance(CIPHER);
            pCipher.init(Cipher.DECRYPT_MODE, key, ivParamSpec);

            // decrypt the information and write it to the output file
            // this makes the code secure as a CipherInputStream is used
            try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, pCipher)) {
                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptedOut.write(bytes, 0, length);
                }
            }
            LOG.info("Decryption complete, open " + decryptedPath);
        }
    }

    /**
     * Generates a secret key from a given password and salt
     *
     * @param password the password used to create the key
     * @param salt     the salt to use to create the key
     * @return the secret key
     */
    public static SecretKey generateSecretKey(String password, byte[] salt) throws NoSuchAlgorithmException {
        SecretKey pbeKey = null;
        try {
            // Generates a key from a given password
            // This makes the code secure as a random salt is used along with a high count number
            // so the generated key is random and more secure
            // Furthermore, PBKDF2 is a NIST approved algorithm and HMAC is used
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, COUNT, KEYLENGTH);
            pbeKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
        } catch (InvalidKeySpecException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the key specification is invalid");
        }
        return pbeKey;
    }
}