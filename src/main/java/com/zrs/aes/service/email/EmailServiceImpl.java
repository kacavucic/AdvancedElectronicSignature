package com.zrs.aes.service.email;

import java.util.Map;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import lombok.AllArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.context.Context;

@AllArgsConstructor
@Service
public class EmailServiceImpl implements EmailService {


  private static final String NOREPLY_ADDRESS = "kacafon98@gmail.com";

  private final JavaMailSender emailSender;

  private final ITemplateEngine thymeleafTemplateEngine;

  @Override
  public void sendRegistrationEmail(@AuthenticationPrincipal Jwt principal, String code)
      throws MessagingException {
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
  public void sendSigningEmail(Map<String, Object> principalClaims, String code)
      throws MessagingException {

    Context context = new Context();
    context.setVariable("user_first_name", principalClaims.get("given_name"));
    context.setVariable("code", code);

    String htmlBody = thymeleafTemplateEngine.process("signingEmail.html", context);

    MimeMessage message = emailSender.createMimeMessage();
    MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
    helper.setFrom(NOREPLY_ADDRESS);
    helper.setTo((String) principalClaims.get("email"));
    helper.setSubject("[AES] Verify Document Signing");
    helper.setText(htmlBody, true);
    emailSender.send(message);
  }
}
