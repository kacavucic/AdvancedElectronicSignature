package com.zrs.aes.exception.error;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.validation.ConstraintViolation;
import lombok.Data;
import org.hibernate.validator.internal.engine.path.PathImpl;
import org.springframework.http.HttpStatus;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;

@Data
public class ApiError {

  private HttpStatus status;
  @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy hh:mm:ss")
  private LocalDateTime timestamp;
  private String message;
  private String debugMessage;
  private List<ApiSubError> subErrors;

  private ApiError() {
    timestamp = LocalDateTime.now();
  }

  public ApiError(HttpStatus status) {
    this();
    this.status = status;
  }

  public ApiError(HttpStatus status, Throwable ex) {
    this();
    this.status = status;
    this.message = "Unexpected error";
    this.debugMessage = ex.getLocalizedMessage();
  }

  public ApiError(HttpStatus status, String message, Throwable ex) {
    this();
    this.status = status;
    this.message = message;
    this.debugMessage = ex.getLocalizedMessage();
  }

  public void addValidationError(List<ObjectError> globalErrors) {
    globalErrors.forEach(
        objectError -> addSubError(new ApiValidationError(objectError.getObjectName(),
            objectError.getDefaultMessage())));
  }

  public void addValidationErrors(List<FieldError> fieldErrors) {
    fieldErrors.forEach(fieldError -> addSubError(new ApiValidationError(fieldError.getObjectName(),
        fieldError.getField(),
        fieldError.getRejectedValue(),
        fieldError.getDefaultMessage())));
  }

  public void addValidationErrors(Set<ConstraintViolation<?>> constraintViolations) {
    constraintViolations.forEach(this::addValidationError);
  }

  private void addSubError(ApiSubError subError) {
    if (subErrors == null) {
      subErrors = new ArrayList<>();
    }
    subErrors.add(subError);
  }

  //    Utility method for adding error of ConstraintViolation. Usually when a @Validated validation fails.
  private void addValidationError(ConstraintViolation<?> cv) {
    if (((PathImpl) cv.getPropertyPath()).getLeafNode().asString().equals("file")) {
      addSubError(new ApiValidationError(cv.getRootBeanClass().getSimpleName(),
          ((PathImpl) cv.getPropertyPath()).getLeafNode().asString(),
          cv.getInvalidValue().getClass().getSimpleName(),
          cv.getMessage()));
    } else {
      addSubError(new ApiValidationError(cv.getRootBeanClass().getSimpleName(),
          ((PathImpl) cv.getPropertyPath()).getLeafNode().asString(),
          cv.getInvalidValue(),
          cv.getMessage()));
    }
  }
}
