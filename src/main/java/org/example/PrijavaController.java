package org.example;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class PrijavaController {

    @FXML
    private TextField nazivSertifikata;

    @FXML
    private Button prijavaButton;

    public int counter = 3;

    @FXML
    void prijavaButtonClick(ActionEvent event) throws CertificateException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
            String certificateName = nazivSertifikata.getText();
            if(certificateName.isEmpty())
            {
                Alert error = new Alert(Alert.AlertType.ERROR);
                error.setContentText("Prazno polje!");
                error.show();
            }
            else
            {
                File certificate = new File(Main.CERTIFICATES_FOLDER+"\\certs\\"+certificateName+".crt");
                if(certificate.exists())
                {
                    Security.addProvider(new BouncyCastleProvider());
                    //Load in the certificate
                    FileInputStream fileInputStream = new FileInputStream(Main.CERTIFICATES_FOLDER+"\\certs\\"+certificateName+".crt");
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate certificate1 = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
                    X509Certificate jdkCert = certificate1; // assuming certificate1 is an instance of the JDK's X509Certificate class
                    X509CertificateHolder signedCertHolder = new X509CertificateHolder(jdkCert.getEncoded());

                    //Load in the CA certificate
                    FileInputStream fileInputStreamCA = new FileInputStream(Main.CERTIFICATES_FOLDER+"\\rootcert.crt");
                    CertificateFactory certificateFactoryCA = CertificateFactory.getInstance("X.509");
                    X509Certificate certificateCA = (X509Certificate) certificateFactoryCA.generateCertificate(fileInputStreamCA);
                    X509Certificate jdkCertCA = certificateCA; // assuming certificate1 is an instance of the JDK's X509Certificate class
                    X509CertificateHolder signedCertHolderCA = new X509CertificateHolder(jdkCertCA.getEncoded());

                    JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();

                    X509Certificate caCertificate = certConverter.getCertificate(signedCertHolderCA);

                    PKIXCertPathBuilderResult result = null;

                    Collection<X509Certificate> caCertificateList = new ArrayList<X509Certificate>();
                    caCertificateList.add(caCertificate);
                    CertStore caCertStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(caCertificateList));

                    PKIXBuilderParameters params = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(caCertificate, null)), new X509CertSelector());
                    params.addCertStore(caCertStore);
                    params.setRevocationEnabled(false);

                    CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
                    try {
                        CertPath certPath = builder.build(params).getCertPath();
                        result = (PKIXCertPathBuilderResult) builder.build(params);
                        if (result != null) {
                            PublicKey publicKey = result.getPublicKey();
                            prijavaButton.getScene().getWindow().hide();
                            Stage prijavaDrugiKorak = new Stage();
                            Parent root = FXMLLoader.load(getClass().getClassLoader().getResource("PrijavaDrugiKorak.fxml"));
                            Scene scene = new Scene(root);
                            prijavaDrugiKorak.setScene(scene);
                            prijavaDrugiKorak.show();
                            prijavaDrugiKorak.setResizable(false);
                        } else {
                            System.out.println("Failed to build certificate path.");
                        }
                    } catch (CertPathBuilderException e) {
                        System.out.println("Failed to build certificate path: " + e.getMessage());
                    }
                }
                else
                {
                    Alert error2 = new Alert(Alert.AlertType.ERROR);
                    error2.setContentText("Nepostojeci sertifikat!");
                    error2.show();
                }
            }
    }

}
