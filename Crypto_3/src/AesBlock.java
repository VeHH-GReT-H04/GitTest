//https://www.youtube.com/watch?v=TU7NT6NqtSQ - aes
//https://habr.com/ru/post/444814/  -   crypto java
// длина блока 128 бит = 16 байт; ключ 128/192/256 бит. в лабе 128 = 16 байт
//http://kryptography.narod.ru/block.html       -еще раз про все режимы
//когда делаешь doFinal - он сам дополняет данные

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AesBlock
{
    private static final byte block_size = 16;
    private static final int int_zero = 0;
    public static byte[] AesBlockEncrypt (SecretKey key, byte[] data, boolean isFinalBlock, String padding) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException
    {
        byte [] CipherText = new byte[block_size];
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);      // error with parameter byte[] key??
        if(isFinalBlock)
            {
                if(data.length < block_size)                //проверяем, что если размер финального блока меньше, то создаем новый блок - нужного размера, записываем и дополняем PKCS7
                {
                    int padding_int = block_size - data.length;     //значение и число байтов для добавления
                    byte padding_byte = (byte)padding_int;
                    byte[] full_block = new byte[block_size];
                    System.arraycopy(data, int_zero, full_block, int_zero, data.length);    //перенесли данные
                    for (int i = data.length; i < block_size; i++)
                    {
                        full_block[i] = padding_byte;
                    }
                    CipherText = cipher.update(full_block);                     //по идее, когда мы шифруем последний блок, мы должны вызвать функцию doFinal, которая автоматичекий дополнит блок до нужного размера. Но если я ее вызываю, она дополняет блок до размера 32 по какому-то алгоритму и ты не можешь понять, как изменить этот размер и этот алгоритм. Почитай еще или спроси!!!!
                }
                else                                        //если блок послдений, но его размер совпадает с нужным
                {
                    CipherText = cipher.update(data);
                }
            }
        else                                                        //для обычных блоков
            {
                CipherText = cipher.update(data);
            }
        return  CipherText;
    }


    public static byte[] AesBlockDecrypt (SecretKey key, byte[] data, boolean isFinalBlock, String padding) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,  IllegalBlockSizeException
    {
        byte [] PlainText = new byte[block_size];
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
            PlainText = cipher.update(data);
       // for (byte b: PlainText)
         //   System.out.print((char)b);
        //System.out.print(PlainText + "AAAAAAAAAAAAAAAAAAAA\n");
       // System.out.print(PlainText.length);
        //return  cipher.update(data);
        return PlainText;
    }

}
