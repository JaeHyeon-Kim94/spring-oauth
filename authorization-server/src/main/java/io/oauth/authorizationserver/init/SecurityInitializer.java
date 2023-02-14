package io.oauth.authorizationserver.init;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

@Component
public class SecurityInitializer implements ApplicationRunner {

    private final RegisteredClientRepository registeredClientRepository;

    public SecurityInitializer(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        RegisteredClient registeredClient = defaultRegisteredClient();

        RegisteredClient foundClient = registeredClientRepository.findByClientId(registeredClient.getClientId());
        if(foundClient == null){
            registeredClientRepository.save(registeredClient);
        }
    }

    private RegisteredClient defaultRegisteredClient() {
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString());

        RegisteredClient defaultClient = builder
                .clientId("oauth2-client-app")
                .clientSecret("{noop}secret")
                //권한 부여 방식
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                //클라이언트 인증 방식 : Basic, Post
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)

                //redirect uri
                .redirectUri("http://127.0.0.1:8081")
                .redirectUri("http://127.0.0.1:8081/login/oauth2/code/myOAuth")
                //scopes
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope(OidcScopes.PHONE)

                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5L)).build())
                .build();

        return defaultClient;
    }
}
