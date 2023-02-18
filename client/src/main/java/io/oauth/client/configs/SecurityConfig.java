package io.oauth.client.configs;

import io.oauth.client.common.CustomAuthorityMapper;
import io.oauth.client.entrypoint.OAuth2LoginAuthenticationEntrypoint;
import io.oauth.client.handler.CustomOAuth2LoginSuccessHandler;
import io.oauth.client.resolver.CustomeBearerTokenResolver;
import io.oauth.client.service.CustomOAuth2UserService;
import io.oauth.client.service.CustomOidcUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
@Slf4j
@EnableWebSecurity
public class SecurityConfig {
    private final CustomOAuth2UserService customOAuthUserService;
    private final CustomOidcUserService customOidcUserService;
    private final AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;
    private final OAuth2LoginAuthenticationEntrypoint oAuth2LoginAuthenticationEntrypoint;
    private final CustomeBearerTokenResolver customeBearerTokenResolver;
    private final CustomOAuth2LoginSuccessHandler customOAuth2LoginSuccessHandler;
    private final CustomAuthorityMapper customAuthorityMapper;
    private final DefaultOAuth2AuthorizationRequestResolver defaultOAuth2AuthorizationRequestResolver;

    public SecurityConfig(CustomOAuth2UserService customOAuthUserService, CustomOidcUserService customOidcUserService, AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver, OAuth2LoginAuthenticationEntrypoint oAuth2LoginAuthenticationEntrypoint, CustomeBearerTokenResolver customeBearerTokenResolver, CustomOAuth2LoginSuccessHandler customOAuth2LoginSuccessHandler, CustomAuthorityMapper customAuthorityMapper, DefaultOAuth2AuthorizationRequestResolver defaultOAuth2AuthorizationRequestResolver) {
        this.customOAuthUserService = customOAuthUserService;
        this.customOidcUserService = customOidcUserService;
        this.authenticationManagerResolver = authenticationManagerResolver;
        this.oAuth2LoginAuthenticationEntrypoint = oAuth2LoginAuthenticationEntrypoint;
        this.customeBearerTokenResolver = customeBearerTokenResolver;
        this.customOAuth2LoginSuccessHandler = customOAuth2LoginSuccessHandler;
        this.customAuthorityMapper = customAuthorityMapper;
        this.defaultOAuth2AuthorizationRequestResolver = defaultOAuth2AuthorizationRequestResolver;
    }


    @Bean
    public SecurityFilterChain oauth2ClientSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "/login").permitAll()
                .anyRequest().authenticated();


        http.oauth2Login( oauth2LoginConfigurer -> oauth2LoginConfigurer
                .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                        .userService(customOAuthUserService)
                        .oidcUserService(customOidcUserService)
                        .userAuthoritiesMapper(customAuthorityMapper))
                .authorizationEndpoint(authorizationEndpointConfig -> authorizationEndpointConfig
                        .authorizationRequestResolver(defaultOAuth2AuthorizationRequestResolver))
                .successHandler(customOAuth2LoginSuccessHandler)
                .loginPage("/login")
        );

        http
                .oauth2Client( oauth2ClientConfigurer -> {
                    //oauth2ClientConfigurer
                });

        http
                .oauth2ResourceServer(resourceServerConfigurer -> resourceServerConfigurer
                        .authenticationManagerResolver(authenticationManagerResolver)
                        .bearerTokenResolver(customeBearerTokenResolver)
                        .authenticationEntryPoint(oAuth2LoginAuthenticationEntrypoint)
                );

        http
                .logout(logoutConfigurer -> logoutConfigurer
                        .logoutUrl("/logout")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", HttpMethod.GET.name()))
                        .deleteCookies("o_id", "r_id")
                        .logoutSuccessUrl("/")
                        //.addLogoutHandler(jwtLogoutHandler)
                );

        http
                .exceptionHandling( exceptionHandlingConfigurer ->
                        exceptionHandlingConfigurer
                            .accessDeniedHandler((request, response, accessDeniedException)
                                    -> response.sendRedirect("/"))
                            .authenticationEntryPoint((request, response, authException)
                                    -> response.sendRedirect("/login")));

        http.sessionManagement( sessionConfigurer -> sessionConfigurer
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }


}

