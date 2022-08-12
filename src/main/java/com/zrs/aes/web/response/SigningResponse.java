package com.zrs.aes.web.response;

import lombok.Builder;

@Builder
public class SigningResponse {
    private String confirmationMessage;
    private String fileDownloadUri;
    private String documentPath;

    public SigningResponse(String confirmationMessage, String fileDownloadUri, String documentPath) {
        this.confirmationMessage = confirmationMessage;
        this.fileDownloadUri = fileDownloadUri;
        this.documentPath = documentPath;
    }

    public String getConfirmationMessage() {
        return confirmationMessage;
    }

    public void setConfirmationMessage(String confirmationMessage) {
        this.confirmationMessage = confirmationMessage;
    }

    public String getFileDownloadUri() {
        return fileDownloadUri;
    }

    public void setFileDownloadUri(String fileDownloadUri) {
        this.fileDownloadUri = fileDownloadUri;
    }

    public String getDocumentPath() {
        return documentPath;
    }

    public void setDocumentPath(String documentPath) {
        this.documentPath = documentPath;
    }
}
