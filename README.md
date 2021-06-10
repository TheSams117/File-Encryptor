# File Encryptor

### Autores: Sergio A. Lozada Sanchez - Carlos H. Gonzales - Juan Felipe Castillo - Daniel Esteban Guzmán

La aplicación desarollada tiene la capacidad de encriptar y desencriptar archivos. El programa cuenta con un menú principal de tres opciones.
La primera opción permite cifrar un archivo, la segunda opción permite descifrar un archivo cifrado por la aplicación y la tercera opción permite al usuario cerrar la aplicación

El sistema de cifrado usado utiliza una clave simétrica, la cual es solicitada al usuario tanto para encriptar como para desencriptar el contenido. La encriptación se genera desde la clase Cipher, que utiliza el algoritmo AES, con 128 bits para generar la clave y 256 bits de semilla. El programa permite agregar el archivo a cifrar a través de un JFileChooser.

## Clase Cipher

Esta clase contienen todos los métodos necesarios para cifrar el archivo, el primer método retorna una cadena de caracteres y es llamado "calculateSHA1"

```
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
```
Este método lee el archivo que el usuario selecciona y lo pasa a un arreglo de bytes para ser procesado, luego se crea el Hash a partir de la clase MessageDigest de Java, que crea de manera segura un "one-way" Hash. El resultado de este método es llamado SHA1

Luego está el método encryptFile que utiliza los métodos generateSalt, y generateSymetricKey, los cuales se explican de la siguiente manera:

El método generateSalt se encarga de generar la semilla para generar la clave, este método retorna un clave de 32 bytes

```
    public byte[] generateSalt() {
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[BITS_SALTS/8]; /* 256 bits = 32 bytes */
        return bytes;
    }
```

El método generateSymetricKey es el encargado de generar la clave de 128 bits a partir de una cadena de caracteres con el algoritmo PBKDF2. Este algoritmo necesita la semilla generada a partir del método generateSalt, el passphrase o la clave elegida por el usuario para encriptar y como resultado entrega la clave de encriptación en bytes

```
 public byte[] generateSymmetricKey(String passphrase, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2);
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, INTERACTIONS, BITS_GENERATED_KEY);
        SecretKey derivedKey = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(derivedKey.getEncoded(), SYMMETRIC_ALGORITHM);
        return secret.getEncoded();
    }

```

Luego, está el método chiper, que es el encargado de cifrar la información del archivo. Este utiliza la clave con la cual se cifrará y la información a cifrar, y como resultado obtenderemos el texto cifrado en bytes.

```
    public byte[] cipher(byte[] key, byte[] message) throws Exception {
        SecretKey secret = new SecretKeySpec(key, SYMMETRIC_ALGORITHM);
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secret);
        byte[] ciphertext = cipher.doFinal(message);
        return ciphertext;
    }
```

Finalmente, hay un conjunto de métodos encargados de escribir esta información, que está en bytes y pasarlas a un archivo de texto plano.

## Clase Decipher

La clase Decipher contiene los métodos chooseFile y calculateSHA1, al igual que la clase Cipher, la diferencia es que en este último es utilizado el siguiente método:

```
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
```

ValidateSHA1. El cual se encarga de validar que el Hash en el archivo y el hash del archivo descifrado sean iguales, y recibe por parámetro el Hash escrito en el archivo.

Finalmente, la clase Decipher tiene el método decryptFile, el cual utiliza los métodos generateSalt y generateSymmetricKey para desencriptar el archivo. Básicamente, este método utiliza arreglos de byte para usarlos como pasos de información, generar la clave, descifrar el archivo y luego validar los Hash con ValidateSHA1


```
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

```

##Realización
Para la realización del proyecto se consultó la API Criptográfica de Java y se consultaron soluciones en páginas de comunidades de programadores tales como Stackoverflow. El proceso de desarrollo consistió en dividir las funciones del programa en tareas. Estas eran:
1. Realizar encriptación de archivos.
2. Realizar cálculo de hash SHA1 de archivos.
3. Realizar desencriptación de archivos.
4. Unificación de código.

##Dificultades
Principalmente, las dificultades consintieron en comprender el uso de la API Criptográfica de Java. El mayor reto fue lograr la encriptación del archivo en conjunto con el cálculo del hash SHA1. Para lograr esto, al encriptar el archivo, se determinó una cantidad de bytes para el hash y la cantidad restante para la encriptación del archivo.

##Conclusión
En conclusión, el programa desarrollado en Java permite la encriptación y desencriptación de archivos.
