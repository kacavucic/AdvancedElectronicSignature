package com.zrs.aes.response;

import com.zrs.aes.persistence.model.Status;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SigningSessionResponse {
    private String id;
    private String documentName;
    private String status;
    private String addedOn;
}
