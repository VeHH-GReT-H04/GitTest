import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main
{
    private static final int keysize = 128;
    private static final byte block_size = 16;
    private static final byte nonce_size = 4;
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        String Text = "I have no idea what i am doing, but half of it works";
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(keysize);
        SecretKey key = kgen.generateKey();                 //make a key
        System.out.print("Key = ");
        System.out.print(key);

        SecureRandom r = new SecureRandom();              //sdelal iv
        byte[] iv = new byte[block_size];
        r.nextBytes(iv);
        System.out.print("\niv = ");
        System.out.print(iv);

        SecureRandom r2 = new SecureRandom();
        byte[] nonce_counter = new byte[block_size];                //делаю для CTR
        r2.nextBytes(nonce_counter);
        for (int i = nonce_size; i < nonce_size+8; i++)
            nonce_counter[i] = iv[i];
        for (int i = nonce_size+8; i < nonce_counter.length; i++)
            nonce_counter[i] = 0;
        nonce_counter[nonce_counter.length-1] = 1;
        System.out.print("\nnonce_counter = ");
        System.out.print(nonce_counter);

        byte[] data = Text.getBytes();
        System.out.print("\n\nECB\n");
        byte[] CipherText = Encrypt.AesEncrypt(key, data, "ECB", iv);
        for (byte b : CipherText)
            System.out.print(b);                                                        //вывол шифротекста
        System.out.print("   :MyCipherText" + "\n");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] standart = cipher.doFinal(Text.getBytes());
        for (byte b: standart)
            System.out.print(b);
        System.out.print("  :System CipherText" + "\n");

        byte[] PlainText = Decrypt.AesDecrypt(key, CipherText, "ECB", iv);
        for (byte b : PlainText)
            System.out.print((char)b);                                                //вывод полученной расшифровки
        System.out.print("  :My PlainText" + "\n");
        cipher.init(Cipher.DECRYPT_MODE, key);
        standart = cipher.doFinal(standart);
        for (byte b: standart)
            System.out.print((char)b);
        System.out.print("  :System PlainText" + "\n");



        System.out.print("\n\nCBC\n");
        CipherText = Encrypt.AesEncrypt(key, data, "CBC", iv);
        for (byte b : CipherText)
            System.out.print(b);                                                        //вывол шифротекста
        System.out.print("   :MyCipherText" + "\n");
       

        PlainText = Decrypt.AesDecrypt(key, CipherText, "CBC", iv);
        for (byte b : PlainText)
            System.out.print((char)b);                                                //вывод полученной расшифровки
        System.out.print("  :My PlainText" + "\n");



        System.out.print("\n\nCFB\n");
        CipherText = Encrypt.AesEncrypt(key, data, "CFB", iv);
        for (byte b : CipherText)
            System.out.print(b);                                                        //вывол шифротекста
        System.out.print("   :MyCipherText" + "\n");


        PlainText = Decrypt.AesDecrypt(key, CipherText, "CFB", iv);
        for (byte b : PlainText)
            System.out.print((char)b);                                                //вывод полученной расшифровки
        System.out.print("  :My PlainText" + "\n");




        System.out.print("\n\nOFB\n");
        CipherText = Encrypt.AesEncrypt(key, data, "OFB", iv);
        for (byte b : CipherText)
            System.out.print(b);                                                        //вывол шифротекста
        System.out.print("   :MyCipherText" + "\n");


        PlainText = Decrypt.AesDecrypt(key, CipherText, "OFB", iv);
        for (byte b : PlainText)
            System.out.print((char)b);                                                //вывод полученной расшифровки
        System.out.print("  :My PlainText" + "\n");




        System.out.print("\n\nCTR\n");
        CipherText = Encrypt.AesEncrypt(key, data, "CTR", nonce_counter);
        for (byte b : CipherText)
            System.out.print(b);                                                        //вывол шифротекста
        System.out.print("   :MyCipherText" + "\n");



        PlainText = Decrypt.AesDecrypt(key, CipherText, "CTR", nonce_counter);
        for (byte b : PlainText)
            System.out.print((char)b);                                                //вывод полученной расшифровки
        System.out.print("  :My PlainText" + "\n");




    }
}
