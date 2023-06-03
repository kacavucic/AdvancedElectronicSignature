package com.zrs.aes.persistence.model;

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
public class Document {

  @Id
  @Column(name = "signing_session_id")
  @Type(type = "uuid-char")
  private UUID id;

  @OneToOne
  @MapsId
  @JoinColumn(name = "signing_session_id")
  private SigningSession signingSession;

  @Column(nullable = false)
  private String filePath;

  @Column(nullable = false)
  private String fileName;

  @Column(nullable = false)
  private Long addedAt;

  @Column
  private String signedFilePath;

  @Column
  private String signedFileName;

  @Column
  private Long signedAt;
}
