package io.oauth.authorizationserver.configs;

import io.oauth.authorizationserver.provider.FormUserAuthenticationProvider;
import io.oauth.authorizationserver.repository.UserRepository;
import io.oauth.authorizationserver.service.CustomUserDetailsService;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.http.HttpSession;
import java.security.KeyPair;

@EnableWebSecurity
public class DefaultSecurityConfig {


    @Autowired
    private ObjectFactory<HttpSession> httpSessionFactory;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {



        http.authorizeRequests(request ->
                request
                        .antMatchers("/login", "/join", "/members/**/check-duplicated").permitAll()
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
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



        return http.build();
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
