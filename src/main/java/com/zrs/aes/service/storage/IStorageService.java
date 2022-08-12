package com.zrs.aes.service.storage;

import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Path;

public interface IStorageService {

    Path store(MultipartFile file);

    Resource loadAsResource(String fileName);

    Path load(String filename);
}
