import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;

public class Application {
    private static Cipher cipher;
    private static Decipher decipher;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        cipher = new Cipher();
        decipher = new Decipher();

        InputStreamReader entrada = new InputStreamReader(System.in);
        BufferedReader teclado = new BufferedReader (entrada);
        String input = "";
        while (!input.equals("3")){
            System.out.println("Bienvenido, por favor seleccione la acción a realizar");
            System.out.println("1-Cifrar archivo");
            System.out.println("2-Descifrar archivo");
            System.out.println("3-Cerrar la aplicación");

            input = teclado.readLine();

            if(input.equals("1")){
                System.out.println("Escriba la frase para generar la clave simétrica");
                String passphrase = teclado.readLine();
                /* Contraseña para generar la clave de 128 bits */
                cipher.setPassphrase(passphrase);
                /* Escoger archivo para cifrar */
                cipher.chooseFile();
                cipher.calculateSHA1();
                try {
                    cipher.encryptFile();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }else if(input.equals("2")){
                System.out.println("Descifrar archivo");
                System.out.println("Escriba la frase para generar la clave simétrica");
                /* Contraseña para generar la clave de 128 bits */
                String passphrase = teclado.readLine();
                decipher.setPassphrase(passphrase);
                /* Escoger archivo para cifrar */
                decipher.chooseFile();
                //decipher.calculateSHA1();
                try {
                    decipher.decryptFile();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            else if(input.equals("3")){
                System.out.println("Gracias por usar nuestra aplicación.");
            }
        }
        teclado.close();

    }
}
