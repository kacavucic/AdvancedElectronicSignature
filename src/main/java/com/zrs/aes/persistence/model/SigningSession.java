package com.zrs.aes.persistence.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table
public class SigningSession {

    @Id
    @GeneratedValue
    @Type(type = "uuid-char")
    private UUID id;

    @OneToOne(cascade = CascadeType.ALL)
    @PrimaryKeyJoinColumn
    @JsonIgnore
    private Document document;

    @OneToOne(cascade = CascadeType.ALL)
    @PrimaryKeyJoinColumn
    @JsonIgnore
    private Certificate certificate;

    @Column(nullable = false)
    @Type(type = "uuid-char")
    private UUID userId;

    @Column(columnDefinition = "integer default 0")
    private int resendAttempts;

    @Column(columnDefinition = "integer default 0")
    private int signAttempts;

    @Column
    private Long suspendedUntil;

    @Column
    private Boolean consent;

    @Column(nullable = false)
    private Status status;


    public SigningSession(UUID id) {
        this.id = id;
    }
}