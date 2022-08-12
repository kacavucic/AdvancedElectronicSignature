package com.zrs.aes.web.validation;

import org.springframework.web.multipart.MultipartFile;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class FileValidator implements ConstraintValidator<FileConstraint, MultipartFile> {

    @Override
    public void initialize(FileConstraint file) {
    }

    @Override
    public boolean isValid(MultipartFile file, ConstraintValidatorContext context) {
        if (file.isEmpty()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                            "Either no file has been chosen in the multipart form" +
                                    " or the chosen file has no content")
                    .addConstraintViolation();
            return false;
        }

        String contentType = file.getContentType();
        if (!isSupportedContentType(contentType)) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                            "Only PDF files are allowed.")
                    .addConstraintViolation();
            return false;
        }

        return true;
    }

    private boolean isSupportedContentType(String contentType) {
        return contentType.equals("application/pdf");
    }

}
