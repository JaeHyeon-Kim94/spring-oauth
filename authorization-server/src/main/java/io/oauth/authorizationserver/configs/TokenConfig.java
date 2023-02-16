package io.oauth.authorizationserver.configs;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.oauth.authorizationserver.domain.User;
import io.oauth.authorizationserver.model.Principal;
import io.oauth.generator.CustomJwtGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Configuration
public class TokenConfig {

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(){
        //JwtGenerator
        CustomJwtGenerator customJwtGenerator = customJwtGenerator();

        customJwtGenerator.setJwtCustomizer(context -> {
             JwtClaimsSet.Builder claims = context.getClaims();

             Principal principal = (Principal)context.getPrincipal().getPrincipal();
             Map<String, String> attributes = principal.getAttributes();

             claims
                     .subject(String.valueOf(principal.getUserId()));

             for (String s : attributes.keySet()) {
                 claims.claim(s, attributes.get(s));
             }
             claims.build();
         });


        //AccessToken Generator
        OAuth2AccessTokenGenerator oAuth2AccessTokenGenerator = new OAuth2AccessTokenGenerator();

//        oAuth2AccessTokenGenerator.setAccessTokenCustomizer(context -> {
//
//        });

        //RefreshToken Generator
        OAuth2RefreshTokenGenerator oAuth2RefreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(customJwtGenerator, oAuth2AccessTokenGenerator, oAuth2RefreshTokenGenerator);
    }

    @Bean
    public CustomJwtGenerator customJwtGenerator(){
        return new CustomJwtGenerator(jwtEncoder());
    }



    @Bean
    public NimbusJwtEncoder jwtEncoder(){
        return new NimbusJwtEncoder(jwkSource());
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsaKey();

        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    private RSAKey generateRsaKey() {
        //KeyPairGenerator
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("KeyPairGenerator getInstance error ", e.getCause());
        }
        keyGen.initialize(2048);

        //KeyPair from generator
        KeyPair keyPair = keyGen.generateKeyPair();

        //KeyPair to RSAKey
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey)
                .privateKey(rsaPrivateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        return rsaKey;
    }

}
