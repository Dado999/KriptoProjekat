package org.example;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.x509.X509V1CertificateGenerator;


public class Main extends Application {

    public static X509V1CertificateGenerator cGenerator = new X509V1CertificateGenerator();
    public static String ROOT_FOLDER = "Folderi";
    public static String USER_FOLDER = "Folderi\\Korisnici.txt";
    public static String CERTIFICATES_FOLDER ="Folderi\\Sertifikati";
    public static String REPOSITORY_FOLDER = "Folderi\\Repozitorijum";

    public static byte[] iv = {5,-5,-47,-107,2,-114,71,53,-121,-27,-111,108,9,-1,-88,51};

    @Override
    public void start(Stage primaryStage) throws Exception
    {
        Parent root = FXMLLoader.load(getClass().getClassLoader().getResource("Pocetna.fxml"));
        Scene scene = new Scene(root);
        primaryStage.setScene(scene);
        primaryStage.show();
        primaryStage.setResizable(false);
        WatcherThread thread = new WatcherThread();
        thread.start();

    }
    public static void main(String[] args) {
        launch(args);
    }
}