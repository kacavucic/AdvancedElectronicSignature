package com.zrs.aes.util;

import com.zrs.aes.exception.customexceptions.AuthenticationException;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

public final class AuthUtil {

  private AuthUtil() {
    throw new IllegalStateException("Utility class");
  }

  public static String getPrincipalId() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null && authentication.getPrincipal() instanceof Jwt auth) {
      return auth.getClaimAsString("sub");
    } else {
      throw new AuthenticationException(GenericMessage.ERROR_MESSAGE_UNAUTHENTICATED_USER);
    }
  }

  public static String getPrincipalUsername() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null && authentication.getPrincipal() instanceof Jwt auth) {
      return auth.getClaimAsString("username");
    } else {
      throw new AuthenticationException(GenericMessage.ERROR_MESSAGE_UNAUTHENTICATED_USER);
    }
  }

  public static Map<String, Object> getPrincipalClaims() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null && authentication.getPrincipal() instanceof Jwt auth) {
      return auth.getClaims();
    } else {
      throw new AuthenticationException(GenericMessage.ERROR_MESSAGE_UNAUTHENTICATED_USER);
    }
  }
}