package com.zrs.aes.service.storage;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "file")
public class StorageProperties {

    private String uploadDir;
    private String downloadDir;

    private String uploadCertDir;
    private String rootCertPath;

}