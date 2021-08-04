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
    private static int COUNT = 1000;


    /**
     * Main method which checks whether the arguments passed in are correct
     * and if so calls, the corresponding methods.
     *
     * @param args the terminal arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        // Check whether state and the correct number of arguments are given
        if (args.length != 4 || (!args[0].equals("enc") && !args[0].equals("dec"))) {
            System.out.println("Wrong arguments given");
            return;
        }

        String state = args[0];

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
    }

    /**
     * Encrypts a given file, to an output file using the information passed as parameters.
     *
     * @param password the password used to encrypt the file
     * @param inputFile the input file to encrypt
     * @param outputFile the output file of the encrypted information
     */
    public static void encryption(String password, String inputFile, String outputFile) {
        SecureRandom sr = new SecureRandom();

        // create the 16 byte salt
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        // create the 16 byte iv
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
            SecretKey pbeKey = generateSecretKey(password, salt);

            // Create PBE Cipher
            Cipher pbeCipher = Cipher.getInstance(CIPHER);

            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, ivParamSpec);

            // write the salt and IV to the output file
            fout.write(salt);
            fout.write(iv);

            // encrypt and write the encrypted data to the output file
            try (CipherOutputStream cipherOut = new CipherOutputStream(fout, pbeCipher)) {
                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }
            }
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        LOG.info("Encryption finished, saved at " + encryptedPath);

    }

    /**
     * Decrypts a given file, to an output file using the information passed as parameters.
     *
     * @param password the password used to encrypt the file
     * @param inputFile the input file to encrypt
     * @param outputFile the output file of the encrypted information
     */
    public static void decryption(String password, String inputFile, String outputFile) {
        // Determine where to find the files and find them
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(inputFile);
        final Path decryptedPath = tempDir.resolve(outputFile);

        // try and open the input and output file
        try (InputStream encryptedData = Files.newInputStream(encryptedPath);
        OutputStream decryptedOut = Files.newOutputStream(decryptedPath)){

            // Retrieve the salt and IV from the input file
            byte[] salt = encryptedData.readNBytes(16);
            byte[] initVector = encryptedData.readNBytes(16);
            IvParameterSpec ivParamSpec = new IvParameterSpec(initVector);

            // Generate the secret key
            SecretKey pbeKey = generateSecretKey(password, salt);

            // Create PBE Cipher
            Cipher pbeCipher = Cipher.getInstance(CIPHER);

            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, ivParamSpec);

            // decrypt the information and write it to the output file
            try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, pbeCipher)) {
                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptedOut.write(bytes, 0, length);
                }
            }
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        LOG.info("Decryption complete, open " + decryptedPath);
    }

    /**
     * Generates a secret key from a given password and salt
     *
     * @param password the password used to create the key
     * @param salt the salt to use to create the key
     *
     * @return the secret key
     */
    public static SecretKey generateSecretKey(String password, byte[] salt) {
        SecretKey pbeKey = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, COUNT, KEYLENGTH);
            pbeKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        System.out.println("password=" + Base64.getEncoder().encodeToString(pbeKey.toString().getBytes()));
        return pbeKey;
    }
}