package io.oauth.client.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

public class CustomOAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken)authentication;
        OidcUser principal = (OidcUser) authentication.getPrincipal();
        OidcIdToken idToken = principal.getIdToken();

        addCookie("o_id", idToken.getTokenValue(), response);
        addCookie("r_id", Base64.getEncoder().encodeToString(authenticationToken.getAuthorizedClientRegistrationId().getBytes()), response);


        this.getRedirectStrategy().sendRedirect(request, response, "/");
    }

    private void addCookie(String key, String value, HttpServletResponse response){
        Cookie cookie = new Cookie(key, value);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(60*60*24);
        cookie.setPath("/");

        response.addCookie(cookie);
    }
}
