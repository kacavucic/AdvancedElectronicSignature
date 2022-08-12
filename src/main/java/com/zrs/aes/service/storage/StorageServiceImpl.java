package com.zrs.aes.service.storage;

import com.zrs.aes.web.exception.CustomFileNotFoundException;
import com.zrs.aes.web.exception.StorageException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

@Service
public class StorageServiceImpl implements IStorageService {

    private final Path uploadPath;
    private final Path downloadLocation;

    @Autowired
    public StorageServiceImpl(StorageProperties storageProperties) {
        this.uploadPath = Paths.get(storageProperties.getUploadDir())
                .toAbsolutePath().normalize();
        this.downloadLocation = Paths.get(storageProperties.getDownloadDir())
                .toAbsolutePath().normalize();

        try {
            Files.createDirectories(this.uploadPath);
        } catch (Exception ex) {
            throw new StorageException("Could not create the directory where the uploaded files will be stored.", ex);
        }

        try {
            Files.createDirectories(this.downloadLocation);
        } catch (Exception ex) {
            throw new StorageException("Could not create the directory where files for download will be stored.", ex);
        }
    }

    public Path store(MultipartFile file) {

        Path filePath = Paths.get(file.getOriginalFilename());

        Path targetPath = this.uploadPath.resolve(filePath).normalize().toAbsolutePath();


        if (!targetPath.getParent().equals(this.uploadPath.toAbsolutePath())) {
             /*
                upload-dir
                    file.txt
                    nesto/file.txt
                    /../../file.txt
             */
            throw new StorageException("Cannot store file outside current directory.");
        }

        try {
            Files.copy(file.getInputStream(), targetPath,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new StorageException("Could not store file " + file.getName(), e);
        }

        return targetPath;
    }

    public Resource loadAsResource(String fileName) {
        try {
            Path filePath = this.downloadLocation.resolve(fileName).normalize();
            Resource resource = new UrlResource(filePath.toUri());
            if (resource.exists()) {
                return resource;
            } else {
                throw new CustomFileNotFoundException("File not found " + fileName);
            }
        } catch (MalformedURLException ex) {
            throw new CustomFileNotFoundException("File not found " + fileName, ex);
        }
    }

    @Override
    public Path load(String fileName) {
        return this.uploadPath.resolve(fileName).normalize();
    }

}