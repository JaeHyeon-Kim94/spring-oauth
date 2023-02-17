package io.oauth.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.Map;

public class JwtUtils {

    private static final ObjectMapper om = new ObjectMapper();

    /**
     * @param tokenValue Base64Encoded stringValue of jwt.
     * @return Mapped key-value from claims(JSON String)
     */
    public static Map<String, Object> getClaims(String tokenValue) throws JsonProcessingException {
        String[] split = tokenValue.split("\\.");
        String claims = new String(Base64.getDecoder().decode(split[1]));

        return om.readValue(claims, Map.class);
    }
}
