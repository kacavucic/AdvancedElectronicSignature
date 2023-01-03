package com.zrs.aes.service.storage;

import com.zrs.aes.web.customexceptions.CustomFileNotFoundException;
import com.zrs.aes.web.customexceptions.StorageException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


@Service
public class StorageServiceImpl implements IStorageService {

    private static final String BC_PROVIDER = "BC";
    private final Path uploadPath;
    private final Path downloadLocation;
    private final Path uploadCertPath;
    private final Path rootCertPath;

    @Autowired
    public StorageServiceImpl(StorageProperties storageProperties) {
        this.uploadPath = Paths.get(storageProperties.getUploadDir())
                .toAbsolutePath().normalize();
        this.downloadLocation = Paths.get(storageProperties.getDownloadDir())
                .toAbsolutePath().normalize();
        this.uploadCertPath = Paths.get(storageProperties.getUploadCertDir())
                .toAbsolutePath().normalize();
        this.rootCertPath = Paths.get(storageProperties.getRootCertPath()).toAbsolutePath().normalize();

        try {
            Files.createDirectories(this.uploadPath);
        } catch (Exception ex) {
            throw new StorageException("Could not create the directory where the uploaded files will be stored", ex);
        }

        try {
            Files.createDirectories(this.downloadLocation);
        } catch (Exception ex) {
            throw new StorageException("Could not create the directory where files for download will be stored", ex);
        }

        try {
            Files.createDirectories(this.uploadCertPath);
        } catch (Exception ex) {
            throw new StorageException("Could not create the directory where the uploaded certificates will be stored",
                    ex);
        }
        try {
            Files.createDirectories(this.rootCertPath);
        } catch (Exception ex) {
            throw new StorageException("Could not create the directory where the root certificate will be stored",
                    ex);
        }
    }

    public Path store(MultipartFile file) {

        Path filePath = Paths.get(file.getOriginalFilename());

        Path targetPath = this.uploadPath.resolve(filePath).normalize().toAbsolutePath();


        if (!targetPath.getParent().equals(this.uploadPath.toAbsolutePath())) {
             /*
                upload-dir
                    file.txt
                    nesto/file.txt
                    /../../file.txt
             */
            throw new StorageException("Cannot store file outside current directory");
        }

        try {
            Files.copy(file.getInputStream(), targetPath,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new StorageException("Could not store file: " + file.getName(), e);
        }

        return targetPath;
    }

    public Resource loadAsResource(String fileName, boolean signed) {
        try {
            Path filePath = ((signed) ? this.downloadLocation.resolve(fileName).normalize() :
                    this.uploadPath.resolve(fileName).normalize());
            Resource resource = new UrlResource(filePath.toUri());
            if (resource.exists()) {
                return resource;
            }
            else {
                throw new CustomFileNotFoundException("File not found: " + fileName);
            }
        } catch (MalformedURLException ex) {
            throw new CustomFileNotFoundException("File not found: " + fileName, ex);
        }
    }

    @Override
    public Path load(String fileName) {
        return this.uploadPath.resolve(fileName).normalize();
    }

    @Override
    public Path loadRootCert(String fileName) {
        Path filePath = this.rootCertPath.resolve(fileName).normalize();
        if (Files.exists(filePath)) {
            return filePath;
        }
        else {
            throw new CustomFileNotFoundException("File not found");
        }
    }

    @Override
    public Path loadCert(String fileName) {
        Path filePath = this.uploadCertPath.resolve(fileName).normalize();
        if (Files.exists(filePath)) {
            return filePath;
        }
        else {
            throw new CustomFileNotFoundException("File not found");
        }
    }

    @Override
    public Path store(X509Certificate userCertificate, String keystorePassword)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {


        Path filePath = Paths.get(String.valueOf(userCertificate.getSerialNumber()) + ".jks");

        Path targetPath = this.uploadCertPath.resolve(filePath).normalize().toAbsolutePath();

        if (!targetPath.getParent().equals(this.uploadCertPath.toAbsolutePath())) {
             /*
                upload-dir
                    file.txt
                    nesto/file.txt
                    /../../file.txt
             */
            throw new StorageException("Cannot store certificate outside current directory");
        }

        try {

            // Save the keystore to a file
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keyStore.store(baos, keystorePassword.toCharArray());
            byte[] data = baos.toByteArray();
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            Files.copy(bais, targetPath, StandardCopyOption.REPLACE_EXISTING);

        } catch (IOException e) {
            throw new StorageException("Could not store certificate: " + userCertificate.getSerialNumber(), e);
        }

        return targetPath;

    }

    @Override
    public Path exportKeyPairToKeystoreFile(KeyPair keyPair, X509Certificate certificate, String alias, String fileName,
                                            String storeType, String storePass) {

        Path filePath = Paths.get(fileName);
        Path targetPath = this.uploadCertPath.resolve(filePath).normalize().toAbsolutePath();

        if (!targetPath.getParent().equals(this.uploadCertPath.toAbsolutePath())) {
             /*
                upload-dir
                    file.txt
                    nesto/file.txt
                    /../../file.txt
             */
            throw new StorageException("Cannot store certificate outside current directory");
        }

        try {
            KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
            sslKeyStore.load(null, null);
            sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(), null, new X509Certificate[]{certificate});
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            sslKeyStore.store(baos, storePass.toCharArray());
            byte[] keystoreBytes = baos.toByteArray();
            Files.copy(new ByteArrayInputStream(keystoreBytes), targetPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            throw new StorageException("Could not store certificate: " + fileName, e);
        }

        return targetPath;
    }

    @Override
    public Path exportRootKeyPairToKeystoreFile(KeyPair keyPair, X509Certificate certificate, String alias,
                                                String fileName,
                                                String storeType, String storePass) {

        Path filePath = Paths.get(fileName);
        Path targetPath = this.rootCertPath.resolve(filePath).normalize().toAbsolutePath();

        if (!targetPath.getParent().equals(this.rootCertPath.toAbsolutePath())) {
             /*
                upload-dir
                    file.txt
                    nesto/file.txt
                    /../../file.txt
             */
            throw new StorageException("Cannot store certificate outside current directory");
        }

        try {
            KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
            sslKeyStore.load(null, null);
            sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(), null, new X509Certificate[]{certificate});
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            sslKeyStore.store(baos, storePass.toCharArray());
            byte[] keystoreBytes = baos.toByteArray();
            Files.copy(new ByteArrayInputStream(keystoreBytes), targetPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            throw new StorageException("Could not store certificate: " + fileName, e);
        }

        return targetPath;
    }


    public void deleteKeystore(String fileName) {

        Path filePath = this.uploadCertPath.resolve(fileName).normalize();
        if (Files.exists(filePath)) {
            try {
                Files.delete(filePath);
            } catch (IOException e) {
                throw new StorageException("Could not delete keystore: " + fileName, e);
            }
        }
        else {
            throw new CustomFileNotFoundException("File not found");
        }
    }


}