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

    /**
     * Default constructor
     */
    public TotpService() {
        this.codeGenerator = new DefaultCodeGenerator();
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, new SystemTimeProvider());
    }

    /**
     * Creates OTP code for provided secret using current timestamp and predefined time bucket
     *
     * @param secret Secret used for OTP generation
     *
     * @return Created OTP code with corrresponding details
     */
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

    /**
     * Verifies provided code based on the provided secret
     *
     * @param secret Secret used for OTP code verification
     * @param code OTP code to be verified
     *
     * @return Whether provided code is valid or not
     */
    public boolean verifyCode(String secret, String code) {
        return codeVerifier.isValidCode(secret, code);
    }
}