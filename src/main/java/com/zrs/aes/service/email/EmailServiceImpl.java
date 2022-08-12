package com.zrs.aes.service.email;

import lombok.AllArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.context.Context;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@AllArgsConstructor
@Service
public class EmailServiceImpl implements IEmailService {


    private static final String NOREPLY_ADDRESS = "kacafon98@gmail.com";

    private final JavaMailSender emailSender;

    private final ITemplateEngine thymeleafTemplateEngine;

    @Override
    public void sendRegistrationEmail(@AuthenticationPrincipal Jwt principal, String code) throws MessagingException {
        Context context = new Context();
        context.setVariable("user", principal.getClaimAsString("preferred_username"));
        context.setVariable("code", code);

        String htmlBody = thymeleafTemplateEngine.process("registrationEmail.html", context);

        MimeMessage message = emailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setFrom(NOREPLY_ADDRESS);
        helper.setTo(principal.getClaimAsString("email"));
        helper.setSubject("[AES] Confirm Registration");
        helper.setText(htmlBody, true);
        emailSender.send(message);
    }

    @Override
    public void sendSigningEmail(@AuthenticationPrincipal Jwt principal, String code)
            throws MessagingException {

        Context context = new Context();
        context.setVariable("user_first_name", principal.getClaimAsString("given_name"));
        context.setVariable("code", code);

        String htmlBody = thymeleafTemplateEngine.process("signingEmail.html", context);

        MimeMessage message = emailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setFrom(NOREPLY_ADDRESS);
        helper.setTo(principal.getClaimAsString("email"));
        helper.setSubject("[AES] Verify Document Signing");
        helper.setText(htmlBody, true);
        //helper.addInline("attachment.png", resourceFile);
        emailSender.send(message);
    }
}
