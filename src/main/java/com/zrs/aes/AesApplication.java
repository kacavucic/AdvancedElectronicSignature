package com.zrs.aes;

import com.zrs.aes.service.signing.SigningProperties;
import com.zrs.aes.service.storage.StorageProperties;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableConfigurationProperties({StorageProperties.class, SigningProperties.class})
public class AesApplication {

    public static void main(String[] args) {
        SpringApplication.run(AesApplication.class, args);
    }

    @Bean
    public OpenAPI customOpenAPI(@Value("${springdoc.version}") String appVersion) {
        return new OpenAPI()
                .components(new Components())
                .info(new Info().title("AES API").version(appVersion));
    }

}
