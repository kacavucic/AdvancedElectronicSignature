//package com.zrs.aes.web.response;
//
//import lombok.Builder;
//
//@Builder
//public class UploadFileResponse {
//    private String fileName;
//    private String fileDownloadUri;
//    private String fileType;
//    private long size;
//    private InitiateSigningSessionResponse signingSession;
//
//    public UploadFileResponse(String fileName, String fileDownloadUri, String fileType, long size, InitiateSigningSessionResponse signingSessionDto) {
//        this.fileName = fileName;
//        this.fileDownloadUri = fileDownloadUri;
//        this.fileType = fileType;
//        this.size = size;
//        this.signingSession = signingSessionDto;
//    }
//
//    public String getFileName() {
//        return fileName;
//    }
//
//    public void setFileName(String fileName) {
//        this.fileName = fileName;
//    }
//
//    public String getFileDownloadUri() {
//        return fileDownloadUri;
//    }
//
//    public void setFileDownloadUri(String fileDownloadUri) {
//        this.fileDownloadUri = fileDownloadUri;
//    }
//
//    public String getFileType() {
//        return fileType;
//    }
//
//    public void setFileType(String fileType) {
//        this.fileType = fileType;
//    }
//
//    public long getSize() {
//        return size;
//    }
//
//    public void setSize(long size) {
//        this.size = size;
//    }
//
//    public InitiateSigningSessionResponse getSigningSessionDto() {
//        return signingSession;
//    }
//
//    public void setSigningSessionDto(InitiateSigningSessionResponse signingSessionDto) {
//        this.signingSession = signingSessionDto;
//    }
//}