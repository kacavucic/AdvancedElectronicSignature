package com.zrs.aes.web.error;

import com.zrs.aes.web.customexceptions.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.validation.BindException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Objects;

import static org.springframework.http.HttpStatus.*;

@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
@Slf4j
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

    @Value("${spring.servlet.multipart.max-file-size}")
    private String maxFileSize;

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(
            MissingServletRequestParameterException ex, HttpHeaders headers,
            HttpStatus status, WebRequest request) {
        logger.info(ex.getClass().getName());
        String error = ex.getParameterName() + " parameter is missing";
        ApiError apiError = new ApiError(BAD_REQUEST, error, ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(
            HttpMediaTypeNotSupportedException ex,
            HttpHeaders headers,
            HttpStatus status,
            WebRequest request) {
        logger.info(ex.getClass().getName());
        StringBuilder builder = new StringBuilder();
        builder.append(ex.getContentType());
        builder.append(" media type is not supported. Supported media types are ");
        ex.getSupportedMediaTypes().forEach(t -> builder.append(t).append(", "));
        ApiError apiError =
                new ApiError(HttpStatus.UNSUPPORTED_MEDIA_TYPE, builder.substring(0, builder.length() - 2), ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatus status,
            WebRequest request) {
        logger.info(ex.getClass().getName());
        ApiError apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage("Validation error");
        apiError.addValidationErrors(ex.getBindingResult().getFieldErrors());
        apiError.addValidationError(ex.getBindingResult().getGlobalErrors());
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleBindException(BindException ex, HttpHeaders headers, HttpStatus status,
                                                         WebRequest request) {
        logger.info(ex.getClass().getName());
        ApiError apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage("Binding error");
        apiError.addValidationErrors(ex.getBindingResult().getFieldErrors());
        apiError.addValidationError(ex.getBindingResult().getGlobalErrors());
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(javax.validation.ConstraintViolationException.class)
    public ResponseEntity<ApiError> handleConstraintViolation(
            javax.validation.ConstraintViolationException ex) {
        logger.info(ex.getClass().getName());
        ApiError apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage("Validation error");
        apiError.addValidationErrors(ex.getConstraintViolations());
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ApiError> handleEntityNotFound(
            EntityNotFoundException ex) {
        logger.info(ex.getClass().getName());
        ApiError apiError = new ApiError(NOT_FOUND);
        apiError.setMessage(ex.getMessage());
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        logger.info(ex.getClass().getName());
        ServletWebRequest servletWebRequest = (ServletWebRequest) request;
        log.info("{} to {}", servletWebRequest.getHttpMethod(), servletWebRequest.getRequest().getServletPath());
        String error = "Malformed JSON request";
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, error, ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    // TODO @ResponseStatus
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> handleDataIntegrityViolation(DataIntegrityViolationException ex,
                                                                 WebRequest request) {
        logger.info(ex.getClass().getName());
        if (ex.getCause() instanceof ConstraintViolationException) {
            ApiError apiError = new ApiError(HttpStatus.CONFLICT, "Database error", ex.getCause());
            return new ResponseEntity<>(apiError, apiError.getStatus());
        }
        ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotWritable(HttpMessageNotWritableException ex,
                                                                  HttpHeaders headers, HttpStatus status,
                                                                  WebRequest request) {
        logger.info(ex.getClass().getName());
        String error = "Error writing JSON output";
        ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, error, ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(
            NoHandlerFoundException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        logger.info(ex.getClass().getName());
        ApiError apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(
                String.format("Could not find the %s method for URL %s", ex.getHttpMethod(), ex.getRequestURL()));
        apiError.setDebugMessage(ex.getMessage());
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex,
                                                                         HttpHeaders headers, HttpStatus status,
                                                                         WebRequest request) {
        logger.info(ex.getClass().getName());
        StringBuilder builder = new StringBuilder();
        builder.append(ex.getMethod());
        builder.append(" method is not supported for this request. Supported methods are ");
        Objects.requireNonNull(ex.getSupportedHttpMethods()).forEach(t -> builder.append(t).append(", "));
        ApiError apiError =
                new ApiError(HttpStatus.METHOD_NOT_ALLOWED, builder.toString(), ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(javax.persistence.EntityNotFoundException.class)
    public ResponseEntity<ApiError> handleEntityNotFound(javax.persistence.EntityNotFoundException ex) {
        logger.info(ex.getClass().getName());
        ApiError apiError = new ApiError(HttpStatus.NOT_FOUND, ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiError> handleMethodArgumentTypeMismatch(MethodArgumentTypeMismatchException ex,
                                                                     WebRequest request) {
        logger.info(ex.getClass().getName());
        ApiError apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(
                String.format("The parameter '%s' of value '%s' could not be converted to type '%s'", ex.getName(),
                        ex.getValue(), Objects.requireNonNull(ex.getRequiredType()).getSimpleName()));
        apiError.setDebugMessage(ex.getMessage());
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(MissingServletRequestPartException ex,
                                                                     HttpHeaders headers, HttpStatus status,
                                                                     WebRequest request) {
        logger.info(ex.getClass().getName());
        String error = ex.getRequestPartName() + " part is missing";
        ApiError apiError = new ApiError(BAD_REQUEST, error, ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleAll(Exception ex, WebRequest request) {
        logger.info(ex.getClass().getName());
        ApiError apiError = new ApiError(INTERNAL_SERVER_ERROR, ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//    @ExceptionHandler(InvalidPathException.class)
//    @ResponseStatus(HttpStatus.BAD_REQUEST)
//    public ResponseEntity<ApiError> handleInvalidPathException(InvalidPathException ex) {
//        logger.info(ex.getClass().getName());
//        String error = "Invalid file path.";
//        ApiError apiError = new ApiError(BAD_REQUEST, error, ex);
//        return new ResponseEntity<>(apiError, apiError.getStatus());
//    }

//    @ExceptionHandler(MaxUploadSizeExceededException.class)
//    @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
//    public ResponseEntity<ApiError> handleMaxUploadSizeExceeded(MaxUploadSizeExceededException ex) {
//        logger.info(ex.getClass().getName());
//        String error = "The maximum allowed file size for upload is " + maxFileSize + ".";
//        ApiError apiError = new ApiError(PAYLOAD_TOO_LARGE, error, ex);
//        return new ResponseEntity<>(apiError, apiError.getStatus());
//    }

//    @ExceptionHandler(StorageException.class)
//    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
//    public ResponseEntity<ApiError> handleStorageException(StorageException ex) {
//        logger.info(ex.getClass().getName());
//        String error = "Error while storing file.";
//        ApiError apiError = new ApiError(INTERNAL_SERVER_ERROR, error, ex);
//        return new ResponseEntity<>(apiError, apiError.getStatus());
//    }

//    @ExceptionHandler(UnsignedDocumentException.class)
//    @ResponseStatus(HttpStatus.BAD_REQUEST)
//    public ResponseEntity<ApiError> handleUnsignedDocumentException(UnsignedDocumentException ex) {
//        logger.info(ex.getClass().getName());
//        String error = "Requested document is not signed.";
//        ApiError apiError = new ApiError(BAD_REQUEST, error, ex);
//        return new ResponseEntity<>(apiError, apiError.getStatus());
//    }

//    @ExceptionHandler(InvalidOTPException.class)
//    @ResponseStatus(HttpStatus.BAD_REQUEST)
//    public ResponseEntity<ApiError> handleInvalidOTPException(InvalidOTPException ex) {
//        logger.info(ex.getClass().getName());
//        String error = "Invalid or expired OTP.";
//        ApiError apiError = new ApiError(BAD_REQUEST, error, ex);
//        return new ResponseEntity<>(apiError, apiError.getStatus());
//    }

//    @ExceptionHandler(InvalidStatusException.class)
//    @ResponseStatus(HttpStatus.BAD_REQUEST)
//    public ResponseEntity<ApiError> handleInvalidStatusException(InvalidStatusException ex) {
//        logger.info(ex.getClass().getName());
//        String error = "Invalid status: " + ex.getLocalizedMessage();
//        ApiError apiError = new ApiError(BAD_REQUEST, error, ex);
//        return new ResponseEntity<>(apiError, apiError.getStatus());
//    }

    // TODO https://auth0.com/blog/get-started-with-custom-error-handling-in-spring-boot-java/

//    @ExceptionHandler(ConsentRequiredException.class)
//    @ResponseStatus(HttpStatus.BAD_REQUEST)
//    public ResponseEntity<ApiError> handleConsentRequiredException(ConsentRequiredException ex) {
//        logger.info(ex.getClass().getName());
//        String error = "Consent is required.";
//        ApiError apiError = new ApiError(BAD_REQUEST, error, ex);
//        return new ResponseEntity<>(apiError, apiError.getStatus());
//    }

//    @ExceptionHandler(SigningSessionSuspendedException.class)
//    @ResponseStatus(HttpStatus.CONFLICT)
//    public ResponseEntity<ApiError> handleSigningSessionSuspendedException(SigningSessionSuspendedException ex) {
//        logger.info(ex.getClass().getName());
//        String error = ex.getMessage();
//        ApiError apiError = new ApiError(CONFLICT, error, ex);
//        return new ResponseEntity<>(apiError, apiError.getStatus());
//    }

    //FIXME implement methods for:
    // - 401 unauthorized
    // - 403 forbidden
}