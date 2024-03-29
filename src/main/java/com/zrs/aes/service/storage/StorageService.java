package com.zrs.aes.service.storage;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

public interface StorageService {

  Path store(MultipartFile file);

  Resource loadAsResource(String fileName, boolean signed);

  Path load(String filename);

  Path loadRootCert(String filename);

  Path loadCert(String filename);

  Path store(X509Certificate certificate, String keystorePassword)
      throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException,
      UnrecoverableEntryException;

  Path exportKeyPairToKeystoreFile(KeyPair keyPair, X509Certificate certificate,
      X509Certificate rootCertificate,
      String alias, String fileName,
      String storeType, String keystorePassword);

  Path exportRootKeyPairToKeystoreFile(KeyPair keyPair, X509Certificate certificate, String alias,
      String fileName,
      String storeType, String keystorePassword);

  void deleteKeystore(String filename);

  void deleteFile(Path filePath);
}
