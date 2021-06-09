import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class Decipher extends JPanel {
    public static final int BITS_SALTS = 256;
    public static final String PBKDF2 = "PBKDF2WithHmacSHA1";
    public static final int INTERACTIONS = 655536;
    public static final int BITS_GENERATED_KEY = 128;
    public static final String SYMMETRIC_ALGORITHM = "AES";
    private File fileToDecipher;
    private String passphrase;
    public void chooseFile(){
        System.out.println("Escogiendo archivo");
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File("user.home"));
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            fileToDecipher = fileChooser.getSelectedFile();
        }
    }
    public String calculateSHA1() throws NoSuchAlgorithmException, IOException {
        String directory = fileToDecipher.getParent();
        byte[] key = Files.readAllBytes(Paths.get(directory+"\\decryptedFile"));
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
    public boolean validateSHA1(byte [] hash) throws NoSuchAlgorithmException, IOException {
        String hashFileEncrypted = "";
        String result2 = "";
        boolean isModified = false;
        for ( byte b : hash ) {
            result2 += b+" ";
            hashFileEncrypted += Integer.toHexString(b&255)+" ";
        }
        String hashFileDencrypted = calculateSHA1();
        if(!hashFileDencrypted.equals(hashFileEncrypted)){
            isModified = true;
        }
        return isModified;
    }
    public void decryptFile() throws Exception {
        byte[] salt = generateSalt();
        System.out.println("Numero de bits de la semilla o salt: " + salt.length*8);
        /* generamos la clave simetrica a partir de la frase y de la salt o semilla */
        byte[] key = generateSymmetricKey(passphrase, salt);
        System.out.println("Numero de bits de la clave simetrica generada: " + key.length*8);

        //Path path = main.chooseFile().toPath();
        byte[] fileBytes = Files.readAllBytes(fileToDecipher.toPath());
        /* Esta parte del arreglo contiene el SHA1 del archivo encriptado */
        byte [] hash = Arrays.copyOfRange(fileBytes, 0, 20);
        /* Esta parte del arreglo contiene el archivo encontrado */
        byte [] msg = Arrays.copyOfRange(fileBytes, 20, fileBytes.length);

        /* Se descrifra el contenido del archivo */
        byte[] msgcipher = decipher(key, msg);
        /* Se crea un archivo nuevo descifrado */
        writeDecryptedFile(msgcipher);
        /* Se valida que el SHA1 que traía el archivo cifrado sea igual al archivo descrifrado */
        if (validateSHA1(hash)){
            System.out.println("Tenga cuidado, el archivo ha sido modificado.");
        }
        else{
            System.out.println("El archivo no ha sido modificado");
        }




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
        return secret.getEncoded();
    }
    public void writeDecryptedFile(byte[] msgcipher){
        try {
            String directory = fileToDecipher.getParent();
            File file = new File(directory+"\\decryptedFile");
            OutputStream os = new FileOutputStream(file);

            System.out.println("Guardando el archivo descifrado.");
            os.write(msgcipher);
            System.out.println("Archivo guardado.");
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public byte[] decipher(byte[] key, byte[] message) throws Exception {
        SecretKey secret = new SecretKeySpec(key, SYMMETRIC_ALGORITHM);
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secret);
        byte[] ciphertext = cipher.doFinal(message);
        return ciphertext;
    }

    public String getPassphrase() {
        return passphrase;
    }

    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }
}
