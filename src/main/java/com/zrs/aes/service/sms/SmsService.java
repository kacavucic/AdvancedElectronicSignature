package com.zrs.aes.service.sms;

import java.util.Map;

public interface SmsService {

  void sendSigningSms(Map<String, Object> principalClaims, String code);
}