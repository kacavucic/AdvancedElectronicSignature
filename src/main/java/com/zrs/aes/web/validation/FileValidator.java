package com.zrs.aes.web.validation;

import org.springframework.web.multipart.MultipartFile;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class FileValidator implements ConstraintValidator<FileConstraint, MultipartFile> {

//    @Value("${spring.servlet.multipart.max-file-size}")
//    private String maxFileSize;

    @Override
    public void initialize(FileConstraint file) {
    }

    @Override
    public boolean isValid(MultipartFile file, ConstraintValidatorContext context) {

        String contentType = file.getContentType();
        boolean valid = true;

        if (contentType != null) {
            if (!isSupportedContentType(contentType)) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate(
                                "Only PDF files are allowed")
                        .addConstraintViolation();

                valid = false;
            }
        }

        if (file.isEmpty()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                            "Either no file has been chosen" +
                                    " or the chosen file has no content")
                    .addConstraintViolation();
            valid = false;
        }

        return valid;
    }

    private boolean isSupportedContentType(String contentType) {
        return contentType.equals("application/pdf");
    }

}
