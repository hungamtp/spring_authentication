package com.example.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "app.abac")
public class AbacProperties {
    private int officeHoursStart = 8;
    private int officeHoursEnd = 20;
    private List<String> allowedIpRanges = new ArrayList<>();
}

