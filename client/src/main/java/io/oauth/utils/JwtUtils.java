package io.oauth.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;

public class JwtUtils {

    private static final ObjectMapper om = new ObjectMapper();

    /**
     * @param tokenValue Base64Encoded stringValue of jwt.
     * @return Mapped key-value from claims(JSON String)
     */
    public static Map<String, Object> getClaims(String tokenValue) {
        String[] split = tokenValue.split("\\.");
        String claims = new String(Base64.getDecoder().decode(split[1]));

        try {
            return om.readValue(claims, Map.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("An error occurred during processing IdTokenStringValue to OidcIdToken", e);
        }
    }

    public static OidcIdToken convertTokenValueStringToOidcIdToken(String tokenValue){
        if(!StringUtils.hasText(tokenValue) && tokenValue.split("\\.").length != 3){
            return null;
        }

        Map<String, Object> claims = getClaims(tokenValue);

        Instant iat = Instant.ofEpochSecond((Integer) claims.get("iat"));
        Instant exp = Instant.ofEpochSecond((Integer) claims.get("exp"));

        return new OidcIdToken(tokenValue, iat, exp, claims);
    }
}
