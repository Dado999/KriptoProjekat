package org.example;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import java.util.List;

public class RegistracijaController {

    @FXML
    private TextField Lozinka;

    @FXML
    private TextField korisnickoIme;

    @FXML
    void RegistracijaClick(ActionEvent event) throws Exception {

        String username = korisnickoIme.getText();
        if (isUsernameAvailable(username)) {
            BufferedWriter bw = new BufferedWriter(new FileWriter(Main.USER_FOLDER, true));
            bw.write(korisnickoIme.getText() + "," + Lozinka.getText());
            bw.newLine();
            bw.close();
            Alert success = new Alert(Alert.AlertType.CONFIRMATION);
            success.setContentText("Uspjesno registrovan!");
            success.show();
            certRequest(korisnickoIme.getText());
            createKey(korisnickoIme.getText());
        } else {
            Alert error = new Alert(Alert.AlertType.ERROR);
            error.setContentText("Greska! Korisnicko ime zauzeto! Koristi novo!");
            error.show();
        }

    }

    boolean isUsernameAvailable(String username) throws IOException {
        List<String> users = Files.readAllLines(Paths.get(Main.USER_FOLDER));
        for (String temp : users) {
            String[] tempArr = temp.split(",");
            if (tempArr[0].equals(username))
                return false;
        }
        return true;
    }

    public void certRequest(String ime) throws OperatorCreationException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        try (FileOutputStream fos = new FileOutputStream(Main.CERTIFICATES_FOLDER + "\\private\\" + ime + ".key")) {
            JcaPEMWriter pemWriter = new JcaPEMWriter(new java.io.OutputStreamWriter(fos));
            PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
                    .setProvider("BC")
                    .build("password".toCharArray());
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(keyPair.getPrivate().getEncoded());
            pemWriter.writeObject(privateKeyInfo, encryptor);
            pemWriter.flush();
        }
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, ime);
        nameBuilder.addRDN(BCStyle.O, "Organization");
        nameBuilder.addRDN(BCStyle.OU, "Organizational Unit");
        nameBuilder.addRDN(BCStyle.L, "BL");
        nameBuilder.addRDN(BCStyle.ST, "RS");
        nameBuilder.addRDN(BCStyle.C, "BH");

        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                nameBuilder.build(),
                keyPair.getPublic());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = signerBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        try (FileOutputStream fos = new FileOutputStream(Main.CERTIFICATES_FOLDER + "\\requests\\" + ime + ".csr")) {
            JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(fos));
            pemWriter.writeObject(csr);
            pemWriter.flush();
        }
    }

    public void createKey(String username) throws NoSuchAlgorithmException, IOException {
        String putanjaDoKeyFile = Main.REPOSITORY_FOLDER + "\\KEYS\\" + username + ".txt";
        File keyFile = new File(putanjaDoKeyFile);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        String base64Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        writeBytesToFile(putanjaDoKeyFile, base64Key.getBytes());
    }

    private static void writeBytesToFile(String filePath, byte[] fileBytes) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(filePath);
        fileOutputStream.write(fileBytes);
        fileOutputStream.close();

    }
}
