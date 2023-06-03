package com.zrs.aes.util;

public final class GenericMessage {

  private GenericMessage() {
    throw new IllegalStateException("Utility class");
  }

  public static final String ERROR_MESSAGE_DOCUMENT_ALREADY_SIGNED = "Document %s is already signed";
  public static final String ERROR_MESSAGE_CANCEL_FORBIDDEN =
      "Only signing sessions with status 'Pending' or 'In Progress' can be canceled";
  public static final String ERROR_MESSAGE_APPROVE_FORBIDDEN =
      "Only signing sessions with status 'Pending' can be approved";
  public static final String ERROR_MESSAGE_CODE_RESEND_FORBIDDEN =
      "Code can be resent only for signing sessions with status 'In Progress'";
  public static final String ERROR_MESSAGE_SIGNING_SESSION_SUSPENDED =
      "Signing session is suspended until %s due to exceeding the number of allowed attempts to resend code";
  public static final String ERROR_MESSAGE_SIGNING_SESSION_REJECTED =
      "Your signing session has been rejected due to entering invalid code 3 times";
  public static final String ERROR_MESSAGE_SIGN_FORBIDDEN =
      "Document can be signed only for signing sessions with status 'In Progress'";
  public static final String ERROR_MESSAGE_INVALID_KEYSTORE_PASSWORD = "Invalid code";
  public static final String ERROR_MESSAGE_DOWNLOAD_UNSIGNED_DOCUMENT_FORBIDDEN =
      "Unsigned document can be downloaded only for signing sessions with status other than 'Signed'";
  public static final String ERROR_MESSAGE_DOWNLOAD_SIGNED_DOCUMENT_FORBIDDEN =
      "Signed document can be downloaded only for signing sessions with status 'Signed'";
  public static final String ERROR_MESSAGE_INVALID_USER =
      "Provided signing session does not belong to current user";
  public static final String ERROR_MESSAGE_UNAUTHENTICATED_USER = "Not authenticated";
  /////////////////////////
  public static final String ERROR_MESSAGE_FILE_NOT_FOUND = "File %s not found";
  public static final String ERROR_MESSAGE_CANNOT_STORE_CERT_OUTSIDE_CURRENT_DIR = "Cannot store certificate outside current directory";
  public static final String ERROR_MESSAGE_CANNOT_STORE_FILE_OUTSIDE_CURRENT_DIR = "Cannot store file outside current directory";
  public static final String ERROR_MESSAGE_CERTIFICATE_WITH_SN_STORING_ERROR = "Could not store certificate with serial number: %s";
  public static final String ERROR_MESSAGE_CERTIFICATE_WITH_FN_STORING_ERROR = "Could not store certificate with file name: %s";
  public static final String ERROR_MESSAGE_CANNOT_CREATE_DIR = "Could not create the directory where %s will be stored";
}
