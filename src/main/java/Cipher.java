import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

public class Cipher extends JPanel {
    public static final int BITS_SALTS = 256;
    public static final String PBKDF2 = "PBKDF2WithHmacSHA1";
    public static final int INTERACTIONS = 655536;
    public static final int BITS_GENERATED_KEY = 128;
    public static final String SYMMETRIC_ALGORITHM = "AES";
    private File fileToCipher;
    private String passphrase;

    public void chooseFile(){
        System.out.println("Escogiendo archivo");
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File("user.home"));
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            fileToCipher = fileChooser.getSelectedFile();
        }
    }

    public String calculateSHA1() throws NoSuchAlgorithmException, IOException {
        byte[] key = Files.readAllBytes(fileToCipher.toPath());
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(key);

        String result = "";
        String result2 = "";
        for ( byte b : hash ) {
            result2 += b+" ";
            result += Integer.toHexString(b&255)+" ";
        }
        System.out.println("SHA1: "+result);
        return result;
    }

    public void encryptFile() throws Exception {
        /* Generar la Salt o semilla */
        byte[] salt = generateSalt();
        System.out.println("Numero de bits de la semilla o salt: " + salt.length*8);
        /* generamos la clave simetrica a partir de la frase y de la salt o semilla */
        byte[] key = generateSymmetricKey(passphrase, salt);
        System.out.println("Numero de bits de la clave simetrica generada: " + key.length*8);
        byte[] msgcipher = cipher(key, Files.readAllBytes(fileToCipher.toPath()));
        writeEncryptedFile(msgcipher);
    }
    public byte[] generateSalt() {
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[BITS_SALTS/8]; /* 256 bits = 32 bytes */
        return bytes;
    }
    public byte[] generateSymmetricKey(String passphrase, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2);
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, INTERACTIONS, BITS_GENERATED_KEY);
        SecretKey derivedKey = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(derivedKey.getEncoded(), SYMMETRIC_ALGORITHM);
        System.out.println("key; "+secret.getEncoded());
        return secret.getEncoded();
    }
    public byte[] cipher(byte[] key, byte[] message) throws Exception {
        SecretKey secret = new SecretKeySpec(key, SYMMETRIC_ALGORITHM);
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secret);
        byte[] ciphertext = cipher.doFinal(message);
        return ciphertext;
    }
    public void writeEncryptedFile(byte[] msgcipher){
        try {
            String directory = fileToCipher.getParent();
            File file = new File(directory+"\\encryptedFile");
            OutputStream os = new FileOutputStream(file);
            System.out.println("Guardando el archivo cifrado.");
            os.write(msgcipher);
            System.out.println("Archivo guardado.");
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public String getPassphrase() {
        return passphrase;
    }
    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }
}
