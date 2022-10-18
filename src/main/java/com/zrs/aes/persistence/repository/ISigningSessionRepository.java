package com.zrs.aes.persistence.repository;

import com.zrs.aes.persistence.model.SigningSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ISigningSessionRepository extends JpaRepository<SigningSession, String> {
    SigningSession findByFilePath(String filePath);

    SigningSession findBySignedFilePath(String signedFilePath);

    List<SigningSession> findByUserId(String userId);
}
