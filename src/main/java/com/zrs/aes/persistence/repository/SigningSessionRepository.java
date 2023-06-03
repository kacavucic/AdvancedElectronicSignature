package com.zrs.aes.persistence.repository;

import com.zrs.aes.persistence.model.SigningSession;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SigningSessionRepository extends JpaRepository<SigningSession, UUID> {

  List<SigningSession> findByUserId(UUID userId);
}
