package com.zrs.aes.service.sms;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "sms")
public class SmsProperties {

  private String twilioAccountSid;
  private String twilioAuthToken;
}
