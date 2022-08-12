package com.zrs.aes.service.storage;

import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Path;

public interface IStorageService {

    public Path store(MultipartFile file);

    public Resource loadAsResource(String fileName);

    public Path load(String filename);
}
