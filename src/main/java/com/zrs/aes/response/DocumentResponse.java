package com.zrs.aes.response;

import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class DocumentResponse {

  private UUID id;

  private String fileName;

  private Long addedAt;

  private String signedFileName;
}
