package com.zrs.aes.persistence.model;

public enum Status {
    SIGNED("Signed"), //download
    PENDING("Pending"), //sign, cancel, down
    IN_PROGRESS("In Progress"), // sign
    CANCELED("Canceled"),
    REJECTED("Rejected");

    // resend otp
    // 3 nova endpointa renew, cancel, reject
    // check if doc is already signed
    //mitm upload pa download aleksandar da objasni
    // max file exceeded i file type i back i front validation

    private String statusString;

    private Status(String statusString) {
        this.statusString = statusString;
    }

    public String getStatusString() {
        return statusString;
    }
}
