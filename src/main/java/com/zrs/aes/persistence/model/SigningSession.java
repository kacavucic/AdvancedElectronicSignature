package com.zrs.aes.persistence.model;

import lombok.*;

import javax.persistence.*;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "signing_session")
public class SigningSession {
    @Id
    private String id;

    // TODO column annotation
    @Column(nullable = false)
    private String userId;

    @Column
    private Long timestamp;

    @Column(length = 6)
    private String otp;

    @Column
    private String secret;

    @Column(columnDefinition = "integer default 0")
    private int otpAttempts;

    @Column(columnDefinition = "integer default 0")
    private int signAttempts;

    @Column
    private Long suspendedUntil;

    @Column(nullable = false)
    private String filePath;

    @Column(nullable = false)
    private String fileName;

    @Column
    private boolean consent;

    @Column(nullable = false)
    private Status status;

    @Column
    private Long addedOn;

    @Column
    private String signedFilePath;

    @Column
    private String signedFileName;

    public SigningSession(String id) {
        this.id = id;
    }
}