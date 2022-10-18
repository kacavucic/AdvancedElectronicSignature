package com.zrs.aes.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DocumentResponse {
    private String name;
    private boolean status;
    private String addedOn;
}
