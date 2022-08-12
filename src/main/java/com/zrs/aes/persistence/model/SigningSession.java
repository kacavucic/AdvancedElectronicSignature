package com.zrs.aes.persistence.model;

import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "signing_session")
public class SigningSession {
    @Id
    private String id;

    @Column(nullable = false)
    private long timestamp;

    @Column(nullable = false, length = 6)
    private String otp;

    @Column
    private String filePath;

    @Column
    private String fileName;

    public SigningSession(String id) {
        this.id = id;
    }
}