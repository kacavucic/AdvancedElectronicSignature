package com.zrs.aes.request;

import java.io.Serializable;
import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApproveSigningSessionRequest implements Serializable {

  @NotNull(message = "Consent must not be null")
  @AssertTrue(message = "Consent is required")
  private Boolean consent;

  private Long certRequestedAt;

}
