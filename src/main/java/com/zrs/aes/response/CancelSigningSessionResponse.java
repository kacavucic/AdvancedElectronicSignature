package com.zrs.aes.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CancelSigningSessionResponse implements Serializable {
    private String id;
}
