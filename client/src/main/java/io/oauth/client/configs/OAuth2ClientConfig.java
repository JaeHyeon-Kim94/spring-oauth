package io.oauth.client.configs;


import io.oauth.client.common.CustomAuthorityMapper;
import io.oauth.client.configs.propertiesconfig.JwtProperties;
import io.oauth.client.entrypoint.OAuth2LoginAuthenticationEntrypoint;
import io.oauth.client.handler.CustomOAuth2LoginSuccessHandler;
import io.oauth.client.provider.CustomRefreshTokenOAuth2AuthorizedClientProvider;
import io.oauth.client.resolver.CustomeBearerTokenResolver;
import io.oauth.client.service.CustomJdbcOAuth2AuthorizedClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.function.Consumer;

@Configuration
public class OAuth2ClientConfig {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    JwtProperties jwtProperties;


    @Bean
    public DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                                        OAuth2AuthorizedClientRepository auth2AuthorizedClientRepository){
        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .provider(customRefreshTokenOAuth2AuthorizedClientProvider())
                .build();

        DefaultOAuth2AuthorizedClientManager defaultOAuth2AuthorizedClientManager
                = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, auth2AuthorizedClientRepository);

        defaultOAuth2AuthorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        defaultOAuth2AuthorizedClientManager.setAuthorizationSuccessHandler((authorizedClient, principal, attributes) -> {
            auth2AuthorizedClientRepository
                    .saveAuthorizedClient(authorizedClient, principal,
                            (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                            (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));


        });


        return defaultOAuth2AuthorizedClientManager;
    }


    @Bean
    public OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository(){
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(oAuth2AuthorizedClientService(null));
    }

    @Bean
    public OAuth2AuthorizedClientService oAuth2AuthorizedClientService(ClientRegistrationRepository clientRegistrationRepository){
        return new CustomJdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository);
    }

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver(){
        return new JwtIssuerAuthenticationManagerResolver(jwtProperties.getTrustedIssuerUri());
    }

    @Bean
    public CustomRefreshTokenOAuth2AuthorizedClientProvider customRefreshTokenOAuth2AuthorizedClientProvider(){
        return new CustomRefreshTokenOAuth2AuthorizedClientProvider();
    }

    @Bean
    public OAuth2LoginAuthenticationEntrypoint oAuth2LoginAuthenticationEntrypoint(OAuth2AuthorizedClientService clientService, OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager) {
        return new OAuth2LoginAuthenticationEntrypoint(clientService, oAuth2AuthorizedClientManager);
    }

    @Bean
    public CustomAuthorityMapper customAuthorityMapper(){
        return new CustomAuthorityMapper();
    }

    @Bean
    public CustomeBearerTokenResolver customeBearerTokenResolver(OAuth2AuthorizedClientService oAuth2AuthorizedClientService){
        return new CustomeBearerTokenResolver(oAuth2AuthorizedClientService);
    }

    @Bean
    public CustomOAuth2LoginSuccessHandler customOAuth2LoginSuccessHandler(){
        return new CustomOAuth2LoginSuccessHandler();
    }

    @Bean
    public DefaultOAuth2AuthorizationRequestResolver defaultOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository){
        DefaultOAuth2AuthorizationRequestResolver defaultOAuth2AuthorizationRequestResolver
                = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        defaultOAuth2AuthorizationRequestResolver.setAuthorizationRequestCustomizer(builder -> {
            builder
                    .attributes( map -> {
                        if(((String)map.get("registration_id")).contains("google")){
                            builder.additionalParameters(additionalParameterForGoogleRefreshToken());
                        }
                    })
                    .build();
        });
        return defaultOAuth2AuthorizationRequestResolver;
    }


    private Consumer<Map<String, Object>> additionalParameterForGoogleRefreshToken(){
        return additionalParameterMap -> {
                additionalParameterMap.put("access_type", "offline");
                additionalParameterMap.put("prompt", "consent");
        };
    }

}
