package com.zrs.aes.persistence.repository;

import com.zrs.aes.persistence.model.SigningSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ISigningSessionRepository extends JpaRepository<SigningSession, UUID> {
    List<SigningSession> findByUserId(UUID userId);
}
