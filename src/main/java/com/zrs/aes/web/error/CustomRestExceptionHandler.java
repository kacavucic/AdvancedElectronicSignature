package com.zrs.aes.web.error;

import com.zrs.aes.web.exception.*;
import org.springframework.beans.TypeMismatchException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.nio.file.InvalidPathException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@RestControllerAdvice
public class CustomRestExceptionHandler extends ResponseEntityExceptionHandler {

    @Value("${spring.servlet.multipart.max-file-size}")
    private String maxFileSize;

    // 400
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(final MethodArgumentNotValidException ex,
                                                                  final HttpHeaders headers, final HttpStatus status,
                                                                  final WebRequest request) {
        final List<String> errors = new ArrayList<>();
        for (final FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.add(error.getField() + ": " + error.getDefaultMessage());
        }
        for (final ObjectError error : ex.getBindingResult().getGlobalErrors()) {
            errors.add(error.getObjectName() + ": " + error.getDefaultMessage());
        }
        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), errors);
        return handleExceptionInternal(ex, apiError, headers, apiError.getStatus(), request);
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleBindException(final BindException ex, final HttpHeaders headers,
                                                         final HttpStatus status, final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final List<String> errors = new ArrayList<>();
        for (final FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.add(error.getField() + ": " + error.getDefaultMessage());
        }
        for (final ObjectError error : ex.getBindingResult().getGlobalErrors()) {
            errors.add(error.getObjectName() + ": " + error.getDefaultMessage());
        }
        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), errors);
        return handleExceptionInternal(ex, apiError, headers, apiError.getStatus(), request);
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleTypeMismatch(final TypeMismatchException ex, final HttpHeaders headers,
                                                        final HttpStatus status, final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final String error =
                ex.getValue() + " value for " + ex.getPropertyName() + " should be of type " + ex.getRequiredType() +
                        ".";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(final MissingServletRequestPartException ex,
                                                                     final HttpHeaders headers, final HttpStatus status,
                                                                     final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final String error = ex.getRequestPartName() + " part is missing.";
        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(
            final MissingServletRequestParameterException ex, final HttpHeaders headers, final HttpStatus status,
            final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final String error = ex.getParameterName() + " parameter is missing.";
        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ExceptionHandler({MethodArgumentTypeMismatchException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<ApiError> handleMethodArgumentTypeMismatch(final MethodArgumentTypeMismatchException ex,
                                                                     final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final String error = ex.getName() + " should be of type " + ex.getRequiredType().getName() + ".";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ExceptionHandler({ConstraintViolationException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<ApiError> handleConstraintViolation(final ConstraintViolationException ex,
                                                              final WebRequest request) {
        logger.info(ex.getClass().getName());

        final List<String> errors = new ArrayList<>();
        for (final ConstraintViolation<?> violation : ex.getConstraintViolations()) {
//            errors.add(violation.getRootBeanClass().getName() + " " + violation.getPropertyPath() + ": " + violation.getMessage());
            errors.add(violation.getMessage());
        }

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), errors);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ExceptionHandler({InvalidPathException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    protected ResponseEntity<ApiError> handleInvalidPathException(final InvalidPathException ex,
                                                                  final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final String error = "Invalid file path.";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    // 404
    @ResponseStatus(HttpStatus.NOT_FOUND)
    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(final NoHandlerFoundException ex,
                                                                   final HttpHeaders headers, final HttpStatus status,
                                                                   final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final String error = "No handler found for " + ex.getHttpMethod() + " " + ex.getRequestURL() + ".";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.NOT_FOUND, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    // 405
    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(
            final HttpRequestMethodNotSupportedException ex, final HttpHeaders headers, final HttpStatus status,
            final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final StringBuilder builder = new StringBuilder();
        builder.append(ex.getMethod());
        builder.append(" method is not supported for this request. Supported methods are ");
        ex.getSupportedHttpMethods().forEach(t -> builder.append(t + " "));

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.METHOD_NOT_ALLOWED, ex.getLocalizedMessage(),
                        builder.toString());
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    // 413
    @ExceptionHandler({MaxUploadSizeExceededException.class})
    @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
    protected ResponseEntity<ApiError> handleMaxUploadSizeExceeded(final MaxUploadSizeExceededException ex,
                                                                   final WebRequest request) {
        logger.info(ex.getClass().getName());


        final String error = "The maximum allowed file size for upload is " + maxFileSize + ".";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.PAYLOAD_TOO_LARGE, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    // 415
    @ResponseStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(final HttpMediaTypeNotSupportedException ex,
                                                                     final HttpHeaders headers, final HttpStatus status,
                                                                     final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final StringBuilder builder = new StringBuilder();
        builder.append(ex.getContentType());
        builder.append(" media type is not supported. Supported media types are ");
        ex.getSupportedMediaTypes().forEach(t -> builder.append(t + " "));

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.UNSUPPORTED_MEDIA_TYPE, ex.getLocalizedMessage(),
                        builder.substring(0, builder.length() - 2));
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    // 500
    @ExceptionHandler({StorageException.class})
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    protected ResponseEntity<ApiError> handleStorageException(final StorageException ex, final WebRequest request) {
        logger.info(ex.getClass().getName());
        //
        final String error = "Error while storing file.";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.INTERNAL_SERVER_ERROR, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ExceptionHandler({Exception.class})
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ApiError> handleAll(final Exception ex, final WebRequest request) {
        logger.info(ex.getClass().getName());
        logger.error("error", ex);
        //
        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.INTERNAL_SERVER_ERROR, ex.getLocalizedMessage(),
                        "error occurred");
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    //FIXME implement methods for:
    // - 401 unauthorized
    // - 403 forbidden

    @ExceptionHandler({UnsignedDocumentException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    protected ResponseEntity<ApiError> handleUnsignedDocumentException(UnsignedDocumentException ex) {
        logger.info(ex.getClass().getName());
        //
        final String error = "Requested document is not signed.";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ExceptionHandler({SigningSessionNotFoundException.class})
    @ResponseStatus(HttpStatus.NOT_FOUND)
    protected ResponseEntity<ApiError> handleSigningSessionNotFoundException(SigningSessionNotFoundException ex) {
        logger.info(ex.getClass().getName());
        //
        final String error = "Signing session not found.";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.NOT_FOUND, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ExceptionHandler({InvalidOTPException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    protected ResponseEntity<ApiError> handleInvalidOTPException(InvalidOTPException ex) {
        logger.info(ex.getClass().getName());

        final String error = "Invalid or expired OTP.";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ExceptionHandler({InvalidStatusException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    protected ResponseEntity<ApiError> handleInvalidStatusException(InvalidStatusException ex) {
        logger.info(ex.getClass().getName());

        final String error = "Invalid status: " + ex.getLocalizedMessage();

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ExceptionHandler({ConsentRequiredException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    protected ResponseEntity<ApiError> handleConsentRequiredException(ConsentRequiredException ex) {
        logger.info(ex.getClass().getName());

        final String error = "Consent is required.";

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }

    @ExceptionHandler({SigningSessionSuspendedException.class})
    @ResponseStatus(HttpStatus.CONFLICT)
    protected ResponseEntity<ApiError> handleSigningSessionSuspendedException(SigningSessionSuspendedException ex) {
        logger.info(ex.getClass().getName());

        final String error = ex.getMessage();

        final ApiError apiError =
                new ApiError(LocalDateTime.now(), HttpStatus.CONFLICT, ex.getLocalizedMessage(), error);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
}
