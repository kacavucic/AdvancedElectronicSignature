package com.zrs.aes;

import com.zrs.aes.service.signing.SigningProperties;
import com.zrs.aes.service.sms.SmsProperties;
import com.zrs.aes.service.storage.StorageProperties;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({StorageProperties.class, SigningProperties.class,
        SmsProperties.class})
@OpenAPIDefinition(info = @Info(title = "Advanced Electronic Signature API",
        description = "REST API for signing documents with advanced electronic signature", version = "1.0.0",
        contact = @Contact(name = "Katarina Vučić", email = "vucic.kat@gmail.com")),
        security = @SecurityRequirement(name = "security_auth"),
        servers = @Server(url = "http://localhost:8081/v1/aes", description = "Resource server URL"))
@SecurityScheme(name = "security_auth", type = SecuritySchemeType.OAUTH2,
        flows = @OAuthFlows(authorizationCode = @OAuthFlow(
                authorizationUrl = "${springdoc.oAuthFlow.authorizationUrl}",
                tokenUrl = "${springdoc.oAuthFlow.tokenUrl}")))
public class AesApplication {

    public static void main(String[] args) {
        SpringApplication.run(AesApplication.class, args);
    }

}
