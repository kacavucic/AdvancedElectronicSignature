package com.zrs.aes.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;
import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApproveSigningSessionRequest implements Serializable {

    @NotNull
    private Boolean consent;
}
