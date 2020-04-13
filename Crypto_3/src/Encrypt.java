//http://kryptography.narod.ru/block.html
//https://ru.stackoverflow.com/questions/1064803/
//https://ru.stackoverflow.com/questions/14243922/



import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Encrypt {
    public static boolean isFinalBlock = false;
    private static final int int_zero = 0;
    private static final byte block_size = 16;

    public static byte[] AesEncrypt(SecretKey key, byte[] data, String mode, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException         //data - целиковое сообщения для шифрования
    {
        int test_block_size;
        int CountBlocks = (int) Math.ceil((double) data.length / block_size);             //делим размер сообщения на размер блока = не целое число double = округляем его в большую сторону = целое число блоков
        byte[] CipherText = new byte[data.length];
        byte[] CipherBlock = new byte[block_size];
        byte[] Block;
        byte[] XOR_block;
        if (mode.equals("ECB"))                  //Electronic Codebook
        {
            CipherText = new byte[CountBlocks*block_size];
            for (int block_number = 0; block_number < CountBlocks; block_number++)                                      //номер блока, с которым работаем
            {
                test_block_size = data.length - block_size * block_number;                 //когда значение станет меньше 16  мы получим размер последнего блока без дополнения
                if (test_block_size < 16)                                                   //создаем последний блок, если его размер меньше необхоимого 16 байт
                {
                    isFinalBlock = true;
                    Block = new byte[test_block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, test_block_size);
                } else                                                                                                    //созаем обычны блок
                {
                    Block = new byte[block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, block_size);
                }
                //System.out.print(Block.length);
                CipherBlock = AesBlock.AesBlockEncrypt(key, Block, isFinalBlock, "PKCS7");                       //вызываем функцию шифрования и получаем блок шифротекста
               // System.out.print(CipherBlock.length);
                System.arraycopy(CipherBlock, int_zero, CipherText, block_size * block_number, CipherBlock.length);       //объединяем каждый блок шифротекста в единый текст
            }
        }


        if (mode.equals("CBC"))      //Cipher Block Chaining
        {
            CipherText = new byte[CountBlocks*block_size];
            for (int block_number = 0; block_number < CountBlocks; block_number++)                                      //номер блока, с которым работаем
            {
                test_block_size = data.length - block_size * block_number;
                if (test_block_size < 16)                                                   //создаем последний блок, если его размер меньше необхоимого 16 байт
                {
                    isFinalBlock = true;
                    Block = new byte[test_block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, test_block_size);
                } else                                                                                                    //созаем обычны блок
                {
                    Block = new byte[block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, block_size);
                }
                int i = 0;
                //XOR_block = new byte[Block.length];                     //можно его не использовать, а просто записывать XOR в Block?
                for (byte element : Block)                            //красиво https://stackoverflow.com/questions/14243922/
                    Block[i] = (byte) (element ^ iv[i++]);           //сделали xor блока исходного текста и вектора. в дальнейшем вектор заменится на шифрованный блок
                CipherBlock = AesBlock.AesBlockEncrypt(key, Block, isFinalBlock, "PKCS7");                              //вызываем функцию шифрования и получаем блок шифротекста
                System.arraycopy(CipherBlock, int_zero, CipherText, block_size * block_number, CipherBlock.length);       //объединяем каждый блок шифротекста в единый текст
                iv = CipherBlock;
            }
        }


        if (mode.equals("CFB"))                 //Cipher Feedback
        {
            CipherText = new byte[data.length];
            for (int block_number = 0; block_number < CountBlocks; block_number++)                                      //номер блока, с которым работаем
            {
                test_block_size = data.length - block_size * block_number;
                if (test_block_size < 16)                                                   //создаем последний блок, если его размер меньше необхоимого 16 байт
                {
                    isFinalBlock = true;
                    Block = new byte[test_block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, test_block_size);
                } else                                                                                                    //созаем обычны блок
                {
                    Block = new byte[block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, block_size);
                }
                CipherBlock = AesBlock.AesBlockEncrypt(key, iv, isFinalBlock, "PKCS7");         //прогнали iv через шифрование
                int i = 0;
                XOR_block = new byte[Block.length];         //можно обойтись без XOR_block но для этого надо менять порядок команд (смотри схему)
                for (byte element : Block)
                    XOR_block[i] = (byte) (element ^ CipherBlock[i++]);
                System.arraycopy(XOR_block, int_zero, CipherText, block_size * block_number, XOR_block.length);       //объединяем каждый блок шифротекста в единый текст
                iv = XOR_block;
            }
        }



        if (mode.equals("OFB"))             //Output Feedback
        {
            CipherText = new byte[data.length];
            for (int block_number = 0; block_number < CountBlocks; block_number++)                                      //номер блока, с которым работаем
            {
                test_block_size = data.length - block_size * block_number;
                if (test_block_size < 16)                                                   //создаем последний блок, если его размер меньше необхоимого 16 байт
                {
                    isFinalBlock = true;
                    Block = new byte[test_block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, test_block_size);
                } else                                                                                                    //созаем обычны блок
                {
                    Block = new byte[block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, block_size);
                }
                CipherBlock = AesBlock.AesBlockEncrypt(key, iv, isFinalBlock, "PKCS7");         //прогнали iv через шифрование
                int i = 0;
                XOR_block = new byte[Block.length];         //можно обойтись без XOR_block но для этого надо менять порядок команд (смотри схему)
                for (byte element : Block)
                    XOR_block[i] = (byte) (element ^ CipherBlock[i++]);
                System.arraycopy(XOR_block, int_zero, CipherText, block_size * block_number, XOR_block.length);       //объединяем каждый блок шифротекста в единый текст
                iv = CipherBlock;
            }
        }


        if (mode.equals("CTR"))
        {
            CipherText = new byte[data.length];
            for (int block_number = 0; block_number < CountBlocks; block_number++)                                      //номер блока, с которым работаем
            {
                iv[iv.length-1] = (byte)block_number;
                test_block_size = data.length - block_size * block_number;
                if (test_block_size < 16)                                                   //создаем последний блок, если его размер меньше необхоимого 16 байт
                {
                    isFinalBlock = true;
                    Block = new byte[test_block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, test_block_size);
                } else                                                                                                    //созаем обычны блок
                {
                    Block = new byte[block_size];
                    System.arraycopy(data, block_size * block_number, Block, int_zero, block_size);
                }
                CipherBlock = AesBlock.AesBlockEncrypt(key, iv, isFinalBlock, "PKCS7");         //прогнали iv через шифрование
                int i = 0;
                XOR_block = new byte[Block.length];
                for (byte element : Block)
                    XOR_block[i] = (byte) (element ^ CipherBlock[i++]);
                System.arraycopy(XOR_block, int_zero, CipherText, block_size * block_number, XOR_block.length);       //объединяем каждый блок шифротекста в единый текст
                                                                            //изменнеие счетчика. он может изменяться от 0 до 127
            }
        }
        return CipherText;
    }
}
