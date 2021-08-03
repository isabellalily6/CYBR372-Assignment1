import java.io.*;
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

    private static final String ALGORITHM = "AES";
    private static String CIPHER = "AES/CBC/PKCS5PADDING";
    private static int COUNT = 1000;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        if ((args.length != 6 && args.length != 4 && args.length != 2)
                && (!args[0].equals("enc") && !args[0].equals("dec") && args[0].equals("info"))) {
            System.out.println("Wrong arguments given");
            return;
        }

        String state = args[0];

        if (state.equals("enc")) {
            CIPHER = args[1];
            System.out.println(args[2]);
            int keyLength = Integer.parseInt(args[2]);
            System.out.println(keyLength);
            String password = args[3];
            String inputFile = args[4];
            String outputFile = args[5];
            encryption(keyLength, password, inputFile, outputFile);
        } else if (state.equals("dec")) {
            String password = args[1];
            String inputFile = args[2];
            String outputFile = args[3];
            decryption(password, inputFile, outputFile);
        } else if (state.equals("info")) {
            System.out.println(getMetaData(args[1]));
        }
    }

    public static void encryption(Integer keyLength, String password, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, InvalidKeySpecException {
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
        //pbeKeySpec = new PBEKeySpec(passwordChar, salt, count, keyLength);
       // keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
        //SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, keyLength);
        SecretKey pbeKey = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), CIPHER);


        // Create PBE Cipher
        Cipher pbeCipher = Cipher.getInstance(CIPHER);
        System.out.println(pbeParamSpec.toString());
        System.out.println(CIPHER);
        // Initialize PBE Cipher with key and parameters
        pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey);

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
        writeMetaData(keyLength, outputFile);

    }

    public static void decryption(String base64SecretKey, String inputFile, String outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, InvalidKeySpecException {

        String info = getMetaData(inputFile);
        String[] data = info.split(" ");
        CIPHER = data[0];
        int keyLength = Integer.parseInt(data[1]);
        System.out.println(CIPHER + " " + keyLength);

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
            byte[] salt = encryptedData.readNBytes(16);
            byte[] initVector = encryptedData.readNBytes(16);
            pbeKeySpec = new PBEKeySpec(passwordChar, salt, count, keyLength);
            keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(passwordChar, salt, 1000, keyLength);
            SecretKey pbeKey = new SecretKeySpec(factory.generateSecret(spec)
                    .getEncoded(), CIPHER);

            // Create PBE Cipher
            Cipher pbeCipher = Cipher.getInstance(CIPHER);

            IvParameterSpec ivParamSpec = new IvParameterSpec(initVector);

            System.out.println("initVector=" + Base64.getEncoder().encodeToString(initVector));
            System.out.println("password=" + Base64.getEncoder().encodeToString(pbeKey.toString().getBytes()));

            pbeParamSpec = new PBEParameterSpec(salt, count, ivParamSpec);
            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey);


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

    public static String getMetaData(String filename) throws IOException {
        //Look for files here
        final Path tempDir = Paths.get("").toAbsolutePath();
        final String filePath = tempDir.resolve(filename).toString();

        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        String currentLine;
        String finalLine = null;
        while((currentLine = reader.readLine()) != null){
            finalLine = currentLine;
        }
        reader.close();

        return finalLine;
    }

    public static void writeMetaData(int keylength, String filename) throws IOException {
        FileWriter fw = new FileWriter(filename, true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.newLine();
        bw.write(CIPHER + " " + keylength);
        bw.close();
        fw.close();
        System.out.println("Append to file");
    }

    public static void removeMetaData(int keylength, String filename) throws IOException {
        FileWriter fw = new FileWriter(filename, true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.newLine();
        bw.write(CIPHER + " " + keylength);
        bw.close();
        fw.close();
        System.out.println("Append to file");
    }
}