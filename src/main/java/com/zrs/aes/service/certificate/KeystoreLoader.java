package com.zrs.aes.service.certificate;

import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.service.storage.StorageService;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class KeystoreLoader {

  private final StorageService storageService;

  public KeyStore loadKeystore(SigningSession signingSession, String keystorePassword)
      throws IOException, GeneralSecurityException {
    Path uploadedCert = storageService.loadCert(
        signingSession.getCertificate().getSerialNumber() + ".pfx");
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(Files.newInputStream(uploadedCert), keystorePassword.toCharArray());
    return keyStore;
  }
}
