package io.oauth.authorizationserver.configs;

import io.oauth.authorizationserver.provider.FormUserAuthenticationProvider;
import io.oauth.authorizationserver.repository.UserRepository;
import io.oauth.authorizationserver.service.CustomUserDetailsService;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.http.HttpSession;

@EnableWebSecurity
public class DefaultSecurityConfig {

    private static final String[] PERMIT_ALL_PATTERN = { "/", "/login", "/join", "/members/**/check-duplicated" };


    @Autowired
    private ObjectFactory<HttpSession> httpSessionFactory;

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> {
            web.ignoring()
                    .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
            ;
        };
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {



        http.authorizeRequests(request ->
                request
                        .antMatchers("/", "/error", "/login", "/join", "/members/**/check-duplicated").permitAll()
                        .antMatchers("/test").hasAuthority("ROLE_TEST")
                        .anyRequest().authenticated());
        http.formLogin(
                formLoginConfigurer -> formLoginConfigurer
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
        );

        http.authenticationProvider(new FormUserAuthenticationProvider(passwordEncoder(), userDetailsService(null), httpSessionFactory));

        //logout config
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .deleteCookies("JSESSIONID", "remember-me");

        //remember-me config
        http
                .rememberMe()
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(3600*24*14);

        //Session Management
        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                .and()
                .invalidSessionUrl("/login")
                .sessionFixation().none();

        //PermitAllFilter
//        http
//                .addFilterAt(permitAllFilter(), FilterSecurityInterceptor.class);



        return http.build();
    }

//    @Bean
//    public PermitAllFilter permitAllFilter() {
//
//        PermitAllFilter permitAllFilter = new PermitAllFilter(PERMIT_ALL_PATTERN);
//        permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
//        permitAllFilter.setAccessDecisionManager(affirmitiveBased);
//
//    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository){
        return new CustomUserDetailsService(userRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
