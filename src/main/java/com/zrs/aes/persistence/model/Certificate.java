package com.zrs.aes.persistence.model;

import java.math.BigInteger;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapsId;
import javax.persistence.OneToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.Type;

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
