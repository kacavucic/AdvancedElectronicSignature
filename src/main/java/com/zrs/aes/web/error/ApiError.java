package com.zrs.aes.web.error;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

@Getter
@Setter
public class ApiError {

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy hh:mm:ss")
    private LocalDateTime timestamp;
    private HttpStatus status;
    private String message;
    private List<String> errors;

    public ApiError(final LocalDateTime timestamp, final HttpStatus status, final String message, final List<String> errors) {
        super();
        this.timestamp = timestamp;
        this.status = status;
        this.message = message;
        this.errors = errors;
    }

    public ApiError(final LocalDateTime timestamp, final HttpStatus status, final String message, final String error) {
        super();
        this.timestamp = timestamp;
        this.status = status;
        this.message = message;
        errors = Arrays.asList(error);
    }

}
