package io.oauth.client.configs.propertiesconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "custom.jwt")
public class JwtProperties{
    private List<String> trustedIssuerUri = new ArrayList<>();

    public List<String> getTrustedIssuerUri() {
        return trustedIssuerUri;
    }

    public void setTrustedIssuerUri(List<String> trustedIssuerUri) {
        this.trustedIssuerUri = trustedIssuerUri;
    }
}
