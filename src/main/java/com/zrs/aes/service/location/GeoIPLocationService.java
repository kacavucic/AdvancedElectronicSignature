package com.zrs.aes.service.location;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import org.springframework.stereotype.Service;

@Service
public class GeoIPLocationService {

  private final DatabaseReader dbReaderCity;

  public GeoIPLocationService() throws IOException {
    File databaseCity = new File(
        "C:\\Users\\ACER\\Desktop\\AdvancedElectronicSignature\\GeoLite2City\\GeoLite2-City.mmdb");
    dbReaderCity = new DatabaseReader.Builder(databaseCity).build();
  }

  public GeoIP getLocation(String ip) throws IOException, GeoIp2Exception {

    InetAddress ipAddress = InetAddress.getByName(ip);
    CityResponse response = dbReaderCity.city(ipAddress);

    String country = response.getCountry().getName();
    String city = response.getCity().getName();
    String latitude = response.getLocation().getLatitude().toString();
    String longitude = response.getLocation().getLongitude().toString();
    return new GeoIP(ip, city, country, latitude, longitude);
  }
}
