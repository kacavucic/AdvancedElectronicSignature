package com.zrs.aes.persistence.model;

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
public class Document {

    @Id
    @Column
    @Type(type = "uuid-char")
    private UUID id;

    @OneToOne
    @MapsId
    @JoinColumn
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
