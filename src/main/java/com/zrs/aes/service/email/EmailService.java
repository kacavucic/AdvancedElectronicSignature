package com.zrs.aes.service.email;


import java.util.Map;
import javax.mail.MessagingException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

public interface EmailService {

  void sendRegistrationEmail(@AuthenticationPrincipal Jwt principal, String code)
      throws MessagingException;

  void sendSigningEmail(Map<String, Object> principalClaims, String code) throws MessagingException;
}