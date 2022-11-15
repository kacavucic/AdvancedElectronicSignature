package com.zrs.aes.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApproveSigningSessionRequest implements Serializable {
    private boolean consent;
}
