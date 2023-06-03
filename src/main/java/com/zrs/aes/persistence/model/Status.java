package com.zrs.aes.persistence.model;

public enum Status {
  SIGNED("Signed"), //download
  PENDING("Pending"), //sign, cancel, down
  IN_PROGRESS("In Progress"), // sign
  CANCELED("Canceled"),
  REJECTED("Rejected");

  // TODO ovo sve
  // vrati keycloak times
  // mitm upload pa download aleksandar da objasni
  // max file exceeded i file type i back i front validation

  private String statusString;

  private Status(String statusString) {
    this.statusString = statusString;
  }

  public String getStatusString() {
    return statusString;
  }
}
