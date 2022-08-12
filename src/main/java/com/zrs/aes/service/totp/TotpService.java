package com.zrs.aes.service.totp;


import com.zrs.aes.persistence.model.OTP;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.springframework.stereotype.Component;

@Component
public class TotpService {

    private final CodeGenerator codeGenerator;
    private final CodeVerifier codeVerifier;

    public TotpService() {
        this.codeGenerator = new DefaultCodeGenerator();
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, new SystemTimeProvider());
    }

    public OTP getCodeObject(String secret) {
        try {
            long currentBucket = Math.floorDiv(new SystemTimeProvider().getTime(), 30);
            long timestamp = new SystemTimeProvider().getTime();
            String code = codeGenerator.generate(secret, currentBucket);
            OTP OTP = new OTP();
            OTP.setId(secret);
            OTP.setTimestamp(timestamp);
            OTP.setOtp(code);
            return OTP;
        } catch (CodeGenerationException e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    public boolean verifyCode(String secret, String code) {
        return codeVerifier.isValidCode(secret, code);
    }
}