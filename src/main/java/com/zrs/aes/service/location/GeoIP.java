package com.zrs.aes.service.location;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ToString
@Getter
@Setter
public class GeoIP {
    private String ipAddress;
    private String city;
    private String country;
    private String latitude;
    private String longitude;

    public GeoIP() {

    }

    public GeoIP(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public GeoIP(String ipAddress, String city, String country, String latitude, String longitude) {
        this.ipAddress = ipAddress;
        this.country = country;
        this.city = city;
        this.latitude = latitude;
        this.longitude = longitude;
    }

}
