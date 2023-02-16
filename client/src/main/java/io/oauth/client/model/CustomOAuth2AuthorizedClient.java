package io.oauth.client.model;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

public class CustomOAuth2AuthorizedClient extends OAuth2AuthorizedClient {

    private final OidcIdToken idToken;

    public CustomOAuth2AuthorizedClient(ClientRegistration clientRegistration, String principalName, OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken, OidcIdToken idToken) {
        super(clientRegistration, principalName, accessToken, refreshToken);
        this.idToken = idToken;
    }

    public OidcIdToken getIdToken() {
        return idToken;
    }
}