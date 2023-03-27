package org.example;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.skin.SliderSkin;
import javafx.scene.input.ContextMenuEvent;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class PrikazFajlovaController implements Initializable {

    static public String folderName;
    static public String password;
    @FXML
    private TextArea fileContents;

    @FXML
    private ListView<Label> fajlovi;

    @FXML
    private Button newFile;

    @FXML
    void saveFile(ActionEvent event) {

    }

    public void selectItem(ContextMenuEvent contextMenuEvent) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

    }
    @FXML
    void newFile(ActionEvent event) throws IOException {
        newFile.getScene().getWindow().hide();
        Stage noviFajl = new Stage();
        Parent root = FXMLLoader.load(getClass().getClassLoader().getResource("NoviFajl.fxml"));
        Scene scene = new Scene(root);

        noviFajl.setScene(scene);
        noviFajl.show();
        noviFajl.setResizable(false);
    }
    public void selectedItem(MouseEvent mouseEvent) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Label chosenLabel = fajlovi.getSelectionModel().getSelectedItem();
        String chosenFile = chosenLabel.getText();
        checkFile(chosenFile,false);
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
       File root = new File(Main.REPOSITORY_FOLDER+"\\0");
        File[] startingFiles = root.listFiles();
        for(File temp : startingFiles)
        {
            try {
                checkFile(temp.getName(),true);
            } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                     IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            }
        }
    }
    public void checkFile(String fileName,boolean calculateHashOrNo) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String finalText = "";
        for(int i = 0 ; i < 4 ; i++)
        {
            List<String> fileText = Files.readAllLines(Paths.get(Main.REPOSITORY_FOLDER+"\\"+i+"\\"+fileName));
            for(String temp1 : fileText)
                finalText+=temp1;
        }
        String decryptedText = decryptText(finalText);
        if(calculateHashOrNo==true && decryptedText!=null) {
            if (calculateHashAndCompare(decryptedText, fileName)) {
                fajlovi.getItems().add(new Label(fileName));
            }
        }
        else if(calculateHashOrNo==false){
            fileContents.setText(decryptedText);
        }
    }
    public String decryptText(String textForDecryption) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String keyFilePath = Main.REPOSITORY_FOLDER + "\\KEYS\\" + folderName + ".txt";
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFilePath));
        byte[] decodedKey = Base64.getDecoder().decode(keyBytes);
        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        byte[] encryptedTextBytes = Base64.getDecoder().decode(textForDecryption);
        byte[] iv = Main.iv;
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decryptedTextBytes=null;
        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        }
        catch (BadPaddingException ex)
        {
            return null;
        }
        String decryptedText = new String(decryptedTextBytes, StandardCharsets.UTF_8);
        return decryptedText;
    }
    public boolean calculateHashAndCompare(String stringToHash,String fileName) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        String keyFilePath = Main.REPOSITORY_FOLDER + "\\KEYS\\" + folderName + ".txt";
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFilePath));
        byte[] decodedKey = Base64.getDecoder().decode(keyBytes);
        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] hashBytes = mac.doFinal(stringToHash.getBytes(StandardCharsets.UTF_8));
        String base64Encoded = Base64.getEncoder().encodeToString(hashBytes);
        String originalHash = Files.readString(Paths.get(Main.REPOSITORY_FOLDER+"\\HASH\\"+fileName));

        return base64Encoded.equals(originalHash) ? true : false;

    }


}
