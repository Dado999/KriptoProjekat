package org.example;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class PrijavaDrugiKorakController {

    @FXML
    private TextField KorisnickoIme;

    @FXML
    private PasswordField Lozinka;

    @FXML
    private Button prijavaButton;


    public int counter=0;
    public boolean profileFound = false;
    public List<String> users = Files.readAllLines(Paths.get(Main.USER_FOLDER));

    public PrijavaDrugiKorakController() throws IOException
    {

    }

    @FXML
    void PrijavaClick(ActionEvent event) throws IOException {
            for (String temp : users) {
                String[] tempArr = temp.split(",");
                if ((tempArr[1].equals(Lozinka.getText()))  && tempArr[0].equals(KorisnickoIme.getText())) {
                    profileFound=true;
                    break;
                }
            }
            if(!profileFound)
            {
                counter++;
                if(counter==3)
                {
                    Alert error1 = new Alert(Alert.AlertType.ERROR);
                    error1.setContentText("E sad si najebo jadrane...");
                    error1.show();
                }
                else {
                    Alert error = new Alert(Alert.AlertType.ERROR);
                    error.setContentText("Pogresno korisnicko ime ili lozinka! imate jos: " + (3 - counter) + " pokusaja!");
                    error.show();
                    profileFound = false;
                }

            }
            else
            {
                profileFound=false;
                counter=0;
                PrikazFajlovaController.folderName = KorisnickoIme.getText();
                PrikazFajlovaController.password = Lozinka.getText();
                prijavaButton.getScene().getWindow().hide();
                Stage prikazFajlova = new Stage();
                Parent root = FXMLLoader.load(getClass().getClassLoader().getResource("PrikazFajlova.fxml"));
                Scene scene = new Scene(root);
                prikazFajlova.setScene(scene);
                prikazFajlova.show();
                prikazFajlova.setResizable(false);
            }
    }

}
