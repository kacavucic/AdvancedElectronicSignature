package com.zrs.aes.persistence.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.UUID;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToOne;
import javax.persistence.PrimaryKeyJoinColumn;
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
public class SigningSession {

  @Id
  @GeneratedValue
  @Type(type = "uuid-char")
  @Column(name = "id")
  private UUID id;

  @OneToOne(mappedBy = "signingSession", cascade = CascadeType.ALL)
  @PrimaryKeyJoinColumn
  @JsonIgnore
  private Document document;

  @OneToOne(mappedBy = "signingSession", cascade = CascadeType.ALL)
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