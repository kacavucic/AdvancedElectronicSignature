package com.zrs.aes.service.totp;


import com.zrs.aes.persistence.model.OneTimePassword;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class TotpService {

    private final CodeGenerator codeGenerator;
    private final CodeVerifier codeVerifier;

    public TotpService() {
        this.codeGenerator = new DefaultCodeGenerator();
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, new SystemTimeProvider());
    }

    public OneTimePassword getCodeObject() {
        try {
            String secret = UUID.randomUUID().toString();
            long currentBucket = Math.floorDiv(new SystemTimeProvider().getTime(), 30);
            long timestamp = new SystemTimeProvider().getTime();
            String code = codeGenerator.generate(secret, currentBucket);

            return OneTimePassword.builder()
                    .secret(secret)
                    .timestamp(timestamp)
                    .otp(code)
                    .build();
        } catch (CodeGenerationException e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    public boolean verifyCode(String secret, String code) {
        return codeVerifier.isValidCode(secret, code);
    }
}