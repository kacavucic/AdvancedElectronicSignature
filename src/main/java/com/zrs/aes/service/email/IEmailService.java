package com.zrs.aes.service.email;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

import javax.mail.MessagingException;

public interface IEmailService {

    void sendRegistrationEmail(@AuthenticationPrincipal Jwt principal, String code) throws MessagingException;

    void sendSigningEmail(@AuthenticationPrincipal Jwt principal, String code) throws MessagingException;
}