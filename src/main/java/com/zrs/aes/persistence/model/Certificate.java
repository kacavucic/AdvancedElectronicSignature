package com.zrs.aes.persistence.model;

import lombok.*;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import java.math.BigInteger;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class Certificate {

    @Id
    @Column(name = "signing_session_id")
    @Type(type = "uuid-char")
    private UUID id;

    @OneToOne
    @MapsId
    @JoinColumn(name = "signing_session_id")
    private SigningSession signingSession;

    @Column(columnDefinition = "DECIMAL(65,0)")
    private BigInteger serialNumber;

    @Column
    private Long requestedAt;

    @Column
    private Long issuedAt;

    @Column(length = 3000)
    private String certificate;

}
