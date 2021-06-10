import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

public class Cipher extends JPanel {
    /**
     * Bits de la semilla
     */
    public static final int BITS_SALTS = 256;
    /**
     * Algoritmo de generación de la clave
     */
    public static final String PBKDF2 = "PBKDF2WithHmacSHA1";
    /**
     * Iteraciones del algoritmo
     */
    public static final int INTERACTIONS = 655536;
    /**
     * Bit para generar clave
     */
    public static final int BITS_GENERATED_KEY = 128;
    /**
     * Algoritmo de encriptación del archivo
     */
    public static final String SYMMETRIC_ALGORITHM = "AES";
    /**
     * Archivo a encriptar
     */
    private File fileToCipher;
    /**
     * Contraseña ingresada por el usuario
     */
    private String passphrase;
    /**
     * Hash sha1 del archivo
     */
    private byte[] sha1;

    /**
     * Metodo encargado de escoger el archivo a encriptar
     */
    public void chooseFile(){
        System.out.println("Escogiendo archivo");
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File("user.home"));
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            fileToCipher = fileChooser.getSelectedFile();
        }
    }

    /**
     * Metodo encargado de calcular el hash SHA1 del archvio a encriptar
     * @return Hash SHA1 del archivo a encriptar.
     */
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
        sha1 = hash;
        return result;
    }

    /**
     * Metodo encargado de llamar los metodos correspondientes para generar clave, cifrar archivo y guardar.
     */
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

    /**
     * Metodo encargado de generar la semilla para generar clave
     * @return Semilla generada de 32 bytes
     */
    public byte[] generateSalt() {
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[BITS_SALTS/8]; /* 256 bits = 32 bytes */
        return bytes;
    }

    /**
     * Metodo encargado de generar la clave de 128 bits apartir de una cadena de caracteres con el algoritmo PBKDF2
     * @param passphrase cadena de caracteres para generar clave
     * @param salt semilla de bytes para generar clave
     * @return retorna la clave de encriptación en bytes
     */
    public byte[] generateSymmetricKey(String passphrase, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2);
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, INTERACTIONS, BITS_GENERATED_KEY);
        SecretKey derivedKey = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(derivedKey.getEncoded(), SYMMETRIC_ALGORITHM);
        return secret.getEncoded();
    }

    /**
     * Metodo encargado de cifrar la información del archivo seleccionado.
     *
     * @param key es la clave con la cual se cifrara el archivo.
     * @param message es la información del archivo sin cifrar en bytes
     * @return retorna la información cifrada en bytes
     */
    public byte[] cipher(byte[] key, byte[] message) throws Exception {
        SecretKey secret = new SecretKeySpec(key, SYMMETRIC_ALGORITHM);
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secret);
        byte[] ciphertext = cipher.doFinal(message);
        return ciphertext;
    }

    /**
     * Este metodo se encarga de escribir en un nuevo archivo la información cifrada y el hash SHA1 del mismo.
     *
     * @param msgcipher bytes del archivo cifrado.
     */
    public void writeEncryptedFile(byte[] msgcipher){
        try {
            String directory = fileToCipher.getParent();

            System.out.println("Guardando el archivo cifrado.");

            File file = new File(directory+"\\encryptedFile");

            OutputStream os = new FileOutputStream(file);
            os.write(sha1);
            os.write(msgcipher);

            System.out.println("Archivo guardado.");
            //os.close();
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
