package com.zrs.aes.response;

import lombok.*;
import org.springframework.core.io.Resource;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DownloadDocumentResponse {
    Resource signedDocument;
}
