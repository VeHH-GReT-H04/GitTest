import sun.awt.geom.AreaOp;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Decrypt
{
    public static boolean isFinalBlock = false;
    private static final int int_zero = 0;
    private static final byte block_size = 16;

    public static byte[] AesDecrypt(SecretKey key, byte[] data, String mode, byte[] iv) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException         //data - целиковое сообщения для шифрования
    {
        int test_block_size;
        int CountBlocks = (int) Math.ceil((double) data.length / block_size);             //делим размер сообщения на размер блока = не целое число double = округляем его в большую сторону = целое число блоков
        byte[] PlainText = new byte[data.length];
        byte[] DeCipherBlock = new byte[block_size];
        byte[] Block;
        byte[] XOR_block;

        if (mode.equals("ECB"))                  //Electronic Codebook. когда расшифровываем его - все блоки стандартной длины
        {
            for (int block_number = 0; block_number < CountBlocks; block_number++)                                      //номер блока, с которым работаем
            {
                Block = new byte[block_size];
                System.arraycopy(data, block_size * block_number, Block, int_zero, block_size);
                DeCipherBlock = AesBlock.AesBlockDecrypt(key, Block, isFinalBlock, "PKCS7");                  //вызываем функцию шифрования и получаем блок шифротекста
                //System.out.print(Block.length + "block.length");
                //System.out.print(DeCipherBlock.length + "DeCipherBlock");
                System.out.print(DeCipherBlock);
                System.arraycopy(DeCipherBlock, int_zero, PlainText, block_size * block_number, DeCipherBlock.length);       //объединяем каждый блок шифротекста в единый текст

            }
        }



        if (mode.equals("CBC"))      //Cipher Block Chaining
        {
            for (int block_number = 0; block_number < CountBlocks; block_number++)                                      //номер блока, с которым работаем
            {
                Block = new byte[block_size];
                System.arraycopy(data, block_size * block_number, Block, int_zero, block_size);
                DeCipherBlock = AesBlock.AesBlockDecrypt(key, Block, isFinalBlock, "PKCS7");
                int i = 0;
                XOR_block = new byte[DeCipherBlock.length];
                for (byte element : DeCipherBlock)
                    XOR_block[i] = (byte) (element ^ iv[i++]);
                System.arraycopy(XOR_block, int_zero, PlainText, block_size * block_number, XOR_block.length);       //объединяем каждый блок шифротекста в единый текст
                i = 0;
                for (byte element : Block)
                    iv[i] = Block[i++];
            }
        }



        if (mode.equals("CFB"))                 //Cipher Feedback
        {
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
                DeCipherBlock = AesBlock.AesBlockEncrypt(key, iv, isFinalBlock, "PKCS7");         //прогнали iv через шифрование
                int i = 0;
                XOR_block = new byte[Block.length];
                //System.out.print(Block.length);
                //System.out.print(DeCipherBlock.length);
                for (byte element : Block)
                    XOR_block[i] = (byte) (element ^ DeCipherBlock[i++]);
                System.arraycopy(XOR_block, int_zero, PlainText, block_size * block_number, XOR_block.length);
                i = 0;
                for (byte element : Block)
                    iv[i] = Block[i++];
            }
        }


        if (mode.equals("OFB"))
        {
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
                DeCipherBlock = AesBlock.AesBlockEncrypt(key, iv, isFinalBlock, "PKCS7");         //прогнали iv через шифрование
                int i = 0;
                XOR_block = new byte[Block.length];
                for (byte element : Block)
                    XOR_block[i] = (byte) (element ^ DeCipherBlock[i++]);
                System.arraycopy(XOR_block, int_zero, PlainText, block_size * block_number, XOR_block.length);
                i = 0;
                for (byte element : Block)
                    iv[i] = DeCipherBlock[i++];
            }
        }



        if (mode.equals("CTR"))
        {
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
                DeCipherBlock = AesBlock.AesBlockEncrypt(key, iv, isFinalBlock, "PKCS7");         //прогнали iv через шифрование
                int i = 0;
                XOR_block = new byte[Block.length];
                for (byte element : Block)
                    XOR_block[i] = (byte) (element ^ DeCipherBlock[i++]);
               // System.out.print(XOR_block + "\n");
                //for (byte b: XOR_block)
                    //System.out.print((char)b);
                System.arraycopy(XOR_block, int_zero, PlainText, block_size * block_number, XOR_block.length);
                                                                          //изменнеие счетчика. он может изменяться от 0 до 127
            }
            //System.out.print(PlainText.length + "\n");
           // System.out.print(PlainText + "\n");
        }


        return PlainText;
    }
}
