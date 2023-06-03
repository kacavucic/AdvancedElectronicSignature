package com.zrs.aes.service.signing;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "keystore")
public class SigningProperties {

  private String storePass;
  private String keyPass;
}
