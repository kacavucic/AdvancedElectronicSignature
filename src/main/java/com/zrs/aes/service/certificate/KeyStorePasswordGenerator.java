package com.zrs.aes.service.certificate;

import org.springframework.stereotype.Service;
import org.thymeleaf.util.StringUtils;

@Service
public class KeyStorePasswordGenerator {
    public String generate() {
        return StringUtils.randomAlphanumeric(7).toUpperCase();
    }
}
