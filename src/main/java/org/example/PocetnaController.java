package org.example;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.stage.Stage;

import java.io.IOException;

public class PocetnaController {

    @FXML
    private Button prijavaButton;

    @FXML
    private Button registracijaButton;

    @FXML
    void PrijavaClick(ActionEvent event) throws IOException {
        prijavaButton.getScene().getWindow().hide();
        Stage registracija = new Stage();
        Parent root = FXMLLoader.load(getClass().getClassLoader().getResource("Prijava.fxml"));
        Scene scene = new Scene(root);

        registracija.setScene(scene);
        registracija.show();
        registracija.setResizable(false);
    }

    @FXML
    void RegistracijaClick(ActionEvent event) throws Exception {
        registracijaButton.getScene().getWindow().hide();
        Stage registracija = new Stage();
        Parent root = FXMLLoader.load(getClass().getClassLoader().getResource("Registracija.fxml"));
        Scene scene = new Scene(root);

        registracija.setScene(scene);
        registracija.show();
        registracija.setResizable(false);
    }

}
