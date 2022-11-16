package com.zrs.aes.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CancelSigningSessionResponse implements Serializable {
    private UUID id;
}
