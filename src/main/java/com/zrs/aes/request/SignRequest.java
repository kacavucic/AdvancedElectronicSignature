package com.zrs.aes.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignRequest implements Serializable {

    @NotBlank
    @Size(min = 7, max = 7)
    @Pattern(regexp = "^[a-zA-Z0-9]*$", message = "Code must contain only alphanumeric characters")
    private String code;
}
