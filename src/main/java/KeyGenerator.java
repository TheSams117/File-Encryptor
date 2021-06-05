import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyGenerator {

    public static final String PBKDF2 = "PBKDF2WithHmacSHA1";
    public static final String SYMMETRIC_ALGORITHM = "AES";
    public static final String ENCODING_MSG = "UTF-8";
    public static final int numeroDeIteraciones = 655536;
    /**
     * numeroDeBitsClaveGenerada
     *      256 y 192 bits nos da como resultado "Illegal key size or default parameters". 
     *      Para poder utilizar mas bits en la clave tenemos que instalar "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files" 
     * */
    public static final int numeroDeBitsClaveGenerada = 128; 
    public static final int numeroDeBitsSalt = 256;

    public static void main(String[] args) throws Exception {
        /* la frase o clave a utilizar para generar la clave simetrica */
        String passphrase = "Esta mi frase";
        KeyGenerator sk = new KeyGenerator();
        /* generamos la Salt o semilla */
        byte[] salt = sk.generateSalt();
        System.out.println("Numero de bits de la semilla o salt: " + salt.length*8);
        /* generamos la clave simetrica a partir de la frase y de la salt o semilla */
        byte[] key = sk.generateSymmetricKey(passphrase, salt);
        System.out.println("Numero de bits de la clave simetrica generada: " + key.length*8);
        /* Mensaje a cifrar y descifrar */
        String thisIsTheMessage = "Este es el mensaje o texto a cifrar!";
        /* ciframos el mensaje */
        System.out.println("Texto a cifrar: " + thisIsTheMessage);
        byte[] msgcipher = sk.cipher(key, Files.readAllBytes(Main.chooseFile().toPath()));
        System.out.println("Mensaje cifrado: " + new String(msgcipher, ENCODING_MSG));
        /* desciframos el mensaje */
        String msg = sk.decipher(key, msgcipher);
        System.out.println("Mensaje descifrado: " + msg);

        /* Conversiones a hexadecimal */
//        String saltInHex = Hex.encodeHexString(salt);
//        String keyInHex = Hex.encodeHexString(key);
//        String msgCipherInHex = Hex.encodeHexString(msgcipher);
//        System.out.println("Semila en hexadecimal: " + saltInHex);
//        System.out.println("Clave simetrica en hexadecimal: " + keyInHex);
//        System.out.println("Mensaje cifrado en hexadecimal: " + msgCipherInHex);
    }

    public byte[] cipher(byte[] key, byte[] message) throws Exception {
        SecretKey secret = new SecretKeySpec(key, SYMMETRIC_ALGORITHM);
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        byte[] ciphertext = cipher.doFinal(message);
        return ciphertext;
    }

    public String decipher(byte[] key, byte[] message) throws Exception {
        SecretKey secret = new SecretKeySpec(key, SYMMETRIC_ALGORITHM);
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secret);
        byte[] ciphertext = cipher.doFinal(message);
        return new String(ciphertext,ENCODING_MSG);
    }

    public byte[] generateSalt() {
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[numeroDeBitsSalt/8]; /* 256 bits = 32 bytes */
        sr.nextBytes(bytes);
        return bytes;
    }

    public byte[] generateSymmetricKey(String passphrase, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2);
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, numeroDeIteraciones, numeroDeBitsClaveGenerada);
        SecretKey derivedKey = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(derivedKey.getEncoded(), SYMMETRIC_ALGORITHM);
        return secret.getEncoded();
    }
}