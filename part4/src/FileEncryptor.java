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
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Isabella Tomaz-Ketley
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());
    private static String CIPHER = "/CBC/PKCS5PADDING";
    // This count makes the code more secure as it adheres to the NIST specifications
    private static final int COUNT = 400000;

    /**
     * Main method which checks whether the arguments passed in are correct
     * and if so calls, the corresponding methods.
     *
     * @param args the terminal arguments
     */
    public static void main(String[] args) {
        // Check whether any arguments are given
        if ((args.length <= 0)) {
            System.out.println("No arguments given");
            return;
        }

        String state = args[0];

        // Check whether state and the correct number of arguments are given, depending on the action
        if(args.length != 6 && args.length != 4 && args.length != 2){
            System.out.println("Wrong number of arguments given");
            return;
        }
        else if ((args.length == 6 && !state.equals("enc")) || (args.length == 4 && !state.equals("dec"))
                || (args.length == 2 && !state.equals("info"))) {
            System.out.println("Wrong arguments given");
            return;
        }

        try {
            if (state.equals("enc")) {
                // if the state is enc, set the cipher and encrypt the file
                String cipher = args[1];
                CIPHER = cipher + CIPHER;
                int keyLength = Integer.parseInt(args[2]);
                encryption(cipher, keyLength, args[3], args[4], args[5]);
            } else if (state.equals("dec")) {
                // if the state is dec, decrypt the file
                decryption(args[1], args[2], args[3]);
            } else if (state.equals("info")) {
                // if the state is info, show the correct info of the file
                System.out.println(getMetaData(args[1], null));
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
     * @param cipher     the cipher algorithm
     * @param keyLength  the length of the key
     * @param password   the password used to encrypt the file
     * @param inputFile  the input file to encrypt
     * @param outputFile the output file of the encrypted information
     */
    public static void encryption(String cipher, Integer keyLength, String password, String inputFile, String outputFile) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        SecureRandom sr = new SecureRandom();

        // create the 16 byte salt
        // this makes the code secure as the salt is randomly generated using SecureRandom
        // this salt makes the code more secure as it is 16 bytes which adheres to the NIST specifications
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        // create the 16 or 8 bytes IV depending on algorithm
        int ivLength = cipher.equals("AES") ? 16 : 8;
        // this makes the code secure as the IV is randomly generated using SecureRandom
        byte[] iv = new byte[ivLength];
        sr.nextBytes(iv);
        IvParameterSpec ivParamSpec = new IvParameterSpec(iv);

        // Determine where to find the files and find them
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(outputFile);
        final Path inputPath = tempDir.resolve(inputFile);

        // try and open the input and output file
        try (InputStream fin = Files.newInputStream(inputPath);
             OutputStream fout = Files.newOutputStream(encryptedPath)) {

            // Create the secret key
            SecretKey key = generateSecretKey(password, salt, keyLength, cipher);

            // Create and initialize the cipher with key and parameters
            Cipher pCipher = Cipher.getInstance(CIPHER);
            pCipher.init(Cipher.ENCRYPT_MODE, key, ivParamSpec);

            writeMetaData(fout, cipher, keyLength, salt, iv);

            // encrypt and write the encrypted data to the output file
            // this makes the code secure as a CipherOutputStream is used
            try (CipherOutputStream cipherOut = new CipherOutputStream(fout, pCipher)) {
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
    public static void decryption(String password, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        // Determine where to find the files and find them
        final Path tempDir = Paths.get("").toAbsolutePath();
        final Path encryptedPath = tempDir.resolve(inputFile);
        final Path decryptedPath = tempDir.resolve(outputFile);

        // try and open the input and output file
        try (InputStream encryptedData = Files.newInputStream(encryptedPath);
             OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {

            // Retrieve the cipher algorithm and key length
            String[] cipherData = getMetaData(null, encryptedData).split(" ");
            String cipher = cipherData[0];
            int keyLength = Integer.parseInt(cipherData[1]);
            CIPHER = cipher + CIPHER;

            // Retrieve the salt and IV
            byte[] salt = encryptedData.readNBytes(16);
            int ivLength = cipher.equals("AES") ? 16 : 8;
            byte[] initVector = encryptedData.readNBytes(ivLength);
            IvParameterSpec ivParamSpec = new IvParameterSpec(initVector);

            // Create the secret key
            SecretKey key = generateSecretKey(password, salt, keyLength, cipher);

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
     * Returns the metadata of a file which contains the cipher algorithm and key length.
     *
     * @param filename      the input file to retrieve the information from.
     *                      This is null if the input stream is given
     * @param encryptedData the stream of corresponding to the file to read.
     *                      This is null is no input stream has been opened yet
     * @return a string containing the retrieved metadata
     */
    public static String getMetaData(String filename, InputStream encryptedData) throws IOException {
        // check whether the input stream is not null, and if it is, open it
        if (encryptedData == null) {
            final Path tempDir = Paths.get("").toAbsolutePath();
            final Path encryptedPath = tempDir.resolve(filename);
            encryptedData = Files.newInputStream(encryptedPath);
        }

        // read the cipher information from the file
        byte[] cipherLength = encryptedData.readNBytes(1);
        byte[] cipher = encryptedData.readNBytes(cipherLength[0]);
        String cipherString = new String(cipher, StandardCharsets.UTF_8);

        // read the keylength information from the file
        byte[] keyLen = encryptedData.readNBytes(1);
        byte[] key = encryptedData.readNBytes(keyLen[0]);
        String keyLengthString = new String(key, StandardCharsets.UTF_8);

        // if the filename is null, then close the file as it doesn't need to be used anymore
        if (filename != null) {
            encryptedData.close();
        }

        return (cipherString + " " + keyLengthString);
    }

    /**
     * Writes the metadata, which is the cipher algorithm and key length, to a given file.
     * This method also writes the salt and IV to the file
     *
     * @param fout      the file stream to write to
     * @param cipher    the cipher to write to the file
     * @param keyLength the key length to write to the file
     * @param salt      the salt to write to the file
     * @param iv        the iv to write to the file
     */
    public static void writeMetaData(OutputStream fout, String cipher, Integer keyLength, byte[] salt, byte[] iv) throws IOException {
        // write the length of the cipher and the cipher to the file
        fout.write(cipher.getBytes().length);
        fout.write(cipher.getBytes());
        // write the length of the key length and the key length to the file
        fout.write(keyLength.toString().getBytes().length);
        fout.write(keyLength.toString().getBytes());
        // write the salt and IV to the file
        fout.write(salt);
        fout.write(iv);
    }

    /**
     * Generates a secret key from a given password, salt, key length and cipher.
     *
     * @param password  the password used to create the key
     * @param salt      the salt to use to create the key
     * @param keyLength the key length to use to create the key
     * @param cipher    the cipher to use to create the key
     * @return the secret key
     */
    public static SecretKey generateSecretKey(String password, byte[] salt, int keyLength, String cipher) throws NoSuchAlgorithmException {
        SecretKey pbeKey = null;
        try {
            // Generates a key from a given password
            // This makes the code secure as a random salt is used along with a high count number
            // so the generated key is random and more secure
            // Furthermore, PBKDF2 is a NIST approved algorithm and HMAC is used
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, COUNT, keyLength);
            pbeKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), cipher);
        } catch (InvalidKeySpecException e) {
            LOG.log(Level.INFO, "Unable to encrypt/decrypt, the key specification is invalid");
        }
        return pbeKey;
    }
}