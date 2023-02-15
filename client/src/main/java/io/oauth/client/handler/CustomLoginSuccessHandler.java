package io.oauth.client.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

public class CustomLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public CustomLoginSuccessHandler() {
    }

    public CustomLoginSuccessHandler(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

//        String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
//        String sub = authentication.getName();
        response.sendRedirect("/");
    }
}
