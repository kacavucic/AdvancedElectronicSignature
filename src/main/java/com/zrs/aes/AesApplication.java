package com.zrs.aes;

import com.zrs.aes.service.signing.SigningProperties;
import com.zrs.aes.service.storage.StorageProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({StorageProperties.class, SigningProperties.class})
public class AesApplication {

    public static void main(String[] args) {
        SpringApplication.run(AesApplication.class, args);
    }


}
