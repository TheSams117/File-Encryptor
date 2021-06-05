import javax.swing.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main extends JPanel {
    public String calculateSHA1(File file) throws NoSuchAlgorithmException, IOException {
        byte[] key = Files.readAllBytes(file.toPath());
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(key);

        String result = "";
        String result2 = "";
        for ( byte b : hash ) {
            result2 += b+" ";
            result += Integer.toHexString(b&255)+" ";
        }

        return result;
    }

    public static File chooseFile(){
//        File file = null;
//        JFileChooser fileChooser = new JFileChooser();
//        fileChooser.setCurrentDirectory(new File("user.home"));
//        int result = fileChooser.showOpenDialog(this);
//        if (result == JFileChooser.APPROVE_OPTION) {
//            file = fileChooser.getSelectedFile();
//        }
        return new File("C:\\Users\\Esteb\\Desktop\\hola.txt");
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        System.out.println("Bienvenido, por favor seleccione la acción a realizar");
        System.out.println("1-Cifrar archivo");
        System.out.println("2-Descifrar archivo");
        InputStreamReader entrada = new InputStreamReader(System.in);
        BufferedReader teclado = new BufferedReader (entrada);
        String input = teclado.readLine();

        if(input.equals("1")){
            Main main = new Main();
            File file = main.chooseFile();
            String SHA1 = main.calculateSHA1(file);
            System.out.println(SHA1);
        }else if(input.equals("2")){
            System.out.println("Descifrar archivo");
        }

        teclado.close();
    }
}
