package org.example;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

public class NoviFajlController {

    @FXML
    private TextArea fileContent;

    @FXML
    private TextField fileName;

    @FXML
    void saveFile(ActionEvent event) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException {
        String textFajla = fileContent.getText();
        String encryptedText = encrypt(textFajla);
        int duzina = encryptedText.length()/4;
        String temp;
        for(int i = 0 ; i < 4; i++)
        {
            if(i<3)
                temp = encryptedText.substring(i*duzina,(i+1)*duzina);
            else
                temp = encryptedText.substring(i*duzina,encryptedText.length());
            switch (i)
            {
                case 0, 1, 2:
                    writeToFile(temp,i,fileName.getText());
                    continue;
                case 3:
                    writeToFile(temp,i,fileName.getText());
            }
        }
    }
    public String encrypt(String stringToEncrypt) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidAlgorithmParameterException {

        String keyFilePath = Main.REPOSITORY_FOLDER + "\\KEYS\\" + PrikazFajlovaController.folderName + ".txt";
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFilePath));
        byte[] decodedKey = Base64.getDecoder().decode(keyBytes);
        SecretKey secreyKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        calculateHashAndStore(stringToEncrypt,secreyKey);

        byte[] iv = Main.iv;

        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secreyKey, new IvParameterSpec(iv));
        byte[] encryptedBytes = cipher.doFinal(stringToEncrypt.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedWithIvBytes = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, encryptedWithIvBytes, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, encryptedWithIvBytes, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(encryptedBytes);

    }
    public void writeToFile(String stringToWrite, int redniBroj,String nazivFajla) throws IOException {
        String fajl = Main.REPOSITORY_FOLDER+"\\"+redniBroj+"\\"+nazivFajla+".txt";
        File file = new File(fajl);
        Files.write(Paths.get(fajl), stringToWrite.getBytes());
    }

    public void calculateHashAndStore(String stringToHash,SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] hashBytes = mac.doFinal(stringToHash.getBytes(StandardCharsets.UTF_8));
        String base64Encoded = Base64.getEncoder().encodeToString(hashBytes);
        Files.write(Paths.get(Main.REPOSITORY_FOLDER+"\\HASH\\"+fileName.getText()+".txt"), base64Encoded.getBytes());
    }

}
