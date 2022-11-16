package com.zrs.aes.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignRequest implements Serializable {

    @NotBlank
    @Size(min = 6, max = 6)
    private String otp;
}
