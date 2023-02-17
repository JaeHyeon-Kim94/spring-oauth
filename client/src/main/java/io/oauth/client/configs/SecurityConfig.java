package io.oauth.client.configs;

import io.oauth.client.entrypoint.OAuth2LoginAuthenticationEntrypoint;
import io.oauth.client.handler.CustomOAuth2LoginSuccessHandler;
import io.oauth.client.resolver.CustomeBearerTokenResolver;
import io.oauth.client.service.CustomOAuth2UserService;
import io.oauth.client.service.CustomOidcUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;

@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private CustomOAuth2UserService customOAuthUserService;

    @Autowired
    private CustomOidcUserService customOidcUserService;;

    @Autowired
    private LogoutHandler jwtLogoutHandler;

    @Autowired
    private AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

    @Autowired
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @Bean
    public SecurityFilterChain oauth2ClientSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeRequests().requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                .antMatchers("/", "/login").permitAll()
                .anyRequest().authenticated();

        http
                .oauth2Client( oauth2ClientConfigurer -> {
                    //oauth2ClientConfigurer
                });

        http.oauth2Login( oauth2LoginConfigurer -> oauth2LoginConfigurer
                .userInfoEndpoint(userInfoEndpointConfig -> {
                    userInfoEndpointConfig
                            .userService(customOAuthUserService)
                            .oidcUserService(customOidcUserService);
                })
                .successHandler(new CustomOAuth2LoginSuccessHandler())
                .loginPage("/login")
        );

        http
                .oauth2ResourceServer(resourceServerConfigurer -> resourceServerConfigurer
                        .authenticationManagerResolver(authenticationManagerResolver)
                        .bearerTokenResolver(new CustomeBearerTokenResolver(oAuth2AuthorizedClientService))
                        .authenticationEntryPoint(oAuth2LoginAuthenticationEntrypoint(null, null))
                );

        http
                .logout(logoutConfigurer -> logoutConfigurer
                        .logoutUrl("/logout")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", HttpMethod.GET.name()))
                        .deleteCookies("o_id")
                        .logoutSuccessUrl("/")
                        .addLogoutHandler(jwtLogoutHandler)
                );

        http.sessionManagement( sessionConfigurer -> sessionConfigurer
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        return http.build();
    }

    @Bean
    public OAuth2LoginAuthenticationEntrypoint oAuth2LoginAuthenticationEntrypoint(OAuth2AuthorizedClientService clientService, OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager) {
        return new OAuth2LoginAuthenticationEntrypoint(clientService, oAuth2AuthorizedClientManager);
    }


}

