package org.example;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WatcherThread extends Thread{

    @Override
    public void run()
    {
        try(WatchService service = FileSystems.getDefault().newWatchService())
        {
            Map<WatchKey, Path> keyMap = new HashMap<>();
            Path path = Paths.get(Main.CERTIFICATES_FOLDER+"\\requests");
            keyMap.put(path.register(service, StandardWatchEventKinds.ENTRY_CREATE),path);

            WatchKey watchKey;

            do {
                watchKey = service.take();
                Path eventDir = keyMap.get(watchKey);

                for (WatchEvent<?> event : watchKey.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();
                    Path eventPath = (Path) event.context();
                    signRequest(eventPath.toString());
                }
            }while(watchKey.reset());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public WatcherThread()
    {

    }
    public void signRequest(String fileName) throws IOException, OperatorCreationException, CertificateException {

        Security.addProvider(new BouncyCastleProvider());
        // Load the encrypted private key from the file
        File keyFile = new File(Main.CERTIFICATES_FOLDER+"\\private\\private2048.key");
        FileReader reader = new FileReader(keyFile);
        PEMParser pemParser = new PEMParser(reader);
        Object obj = pemParser.readObject();
        PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
        PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build("password".toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair keyPair = converter.getKeyPair(encryptedKeyPair.decryptKeyPair(decryptorProvider));

        // Create the certificate request
        String csrFilePath = Main.CERTIFICATES_FOLDER+"\\requests\\"+fileName;
        PemReader pemReader = new PemReader(new FileReader(csrFilePath));
        PemObject pemObject = pemReader.readPemObject();
        pemReader.close();

        byte[] csrBytes = pemObject.getContent();
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

        // Create the certificate builder
        X500Name issuerName = new X500Name("CN=CA tijelo");
        X500Name subjectName = csr.getSubject();
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30); // 30 days ago
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 180); // 1 year from now
        LocalDate notBefore1 = notBefore.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        LocalDate notAfter2 = notAfter.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();

        JcaPEMKeyConverter converter1 = new JcaPEMKeyConverter();
        PublicKey publicKey = converter.getPublicKey(csr.getSubjectPublicKeyInfo());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                Date.from(notBefore1.atStartOfDay().toInstant(ZoneOffset.UTC)),
                Date.from(notAfter2.atStartOfDay().toInstant(ZoneOffset.UTC)),
                subjectName,
                publicKey
        );
        // Create the content signer
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(keyPair.getPrivate());

        // Sign the certificate request and convert the result to X509 certificate
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
        // Create a certificate holder from the signed certificate
        X509CertificateHolder certHolder = new X509CertificateHolder(certificate.getEncoded());

        // Write the certificate to a file
        String name = fileName.substring(0,fileName.length()-4);
        File certFile = new File(Main.CERTIFICATES_FOLDER+"\\certs\\"+name+".crt");
        FileOutputStream outputStream = new FileOutputStream(certFile);
        outputStream.write(certHolder.getEncoded());
        outputStream.close();

        // Load the existing index file
        File indexFile = new File(Main.CERTIFICATES_FOLDER+"\\index.txt");
        List<String> indexLines = Files.readAllLines(Paths.get(indexFile.toURI()));

        String dn = certHolder.getSubject().toString();
        String profile=null;

        byte[] extensionValue = certificate.getExtensionValue(Extension.certificatePolicies.getId());
        if (extensionValue != null) {
            Extensions extensions = Extensions.getInstance(extensionValue);
            Extension certificatePolicies = extensions.getExtension(Extension.certificatePolicies);
            if (certificatePolicies != null) {
                profile = certificatePolicies.toString();
            }
        }

        if(indexLines.isEmpty())
        {
            String newLine = String.format("V\t%s\t%s\t%s\t%s", Date.from(notAfter2.atStartOfDay().toInstant(ZoneOffset.UTC)), 01, profile, dn);
            indexLines.add(newLine);
            Files.write(Paths.get(indexFile.toURI()), indexLines);
        }
        else
        {
            // Extract the fields from the last line of the index file
            String[] fields = indexLines.get(indexLines.size() - 1).split("\t");
            String status = fields[0];
            String date = fields[1];
            String serial = fields[2];
            String profile1 = fields[3];
            String subject = fields[4];

            // Generate a new serial number by incrementing the last one
            BigInteger lastSerial = serial.isEmpty() ? BigInteger.ZERO : new BigInteger(serial, 10);
            BigInteger newSerial = lastSerial.add(BigInteger.ONE);

            // Create a new line for the signed certificate in the index file
            String newLine = String.format("V\t%s\t%s\t%s\t%s", date, newSerial, profile1, subject);

            // Append the new line to the index file and save it
            indexLines.add(newLine);
            Files.write(Paths.get(indexFile.toURI()), indexLines);
        }

        //Updating the serial file
        File serialFile = new File(Main.CERTIFICATES_FOLDER+"\\serial");
        FileInputStream fileInputStream = new FileInputStream(serialFile);
        DataInputStream dataInputStream = new DataInputStream(fileInputStream);

        byte[] serialBytes = new byte[(int)serialFile.length()];
        dataInputStream.readFully(serialBytes);

        BigInteger serialNumber1 = new BigInteger(serialBytes);
        serialNumber = serialNumber1.add(BigInteger.ONE);

        dataInputStream.close();
        fileInputStream.close();

        FileOutputStream fileOutputStream = new FileOutputStream(serialFile);
        DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream);

        dataOutputStream.write(serialNumber.toByteArray());

        dataOutputStream.close();
        fileOutputStream.close();
    }
}
