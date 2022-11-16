package com.zrs.aes.persistence.model;

import lombok.*;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import java.util.UUID;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table
public class OneTimePassword {

    @Id
    @Column
    @Type(type = "uuid-char")
    private UUID id;

    @OneToOne
    @MapsId
    @JoinColumn
    private SigningSession signingSession;

    @Column
    private Long timestamp;

    @Column(length = 6)
    private String otp;

    @Column
    private String secret;
}
