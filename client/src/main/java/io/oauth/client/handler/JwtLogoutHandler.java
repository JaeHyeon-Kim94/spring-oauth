package io.oauth.client.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtLogoutHandler implements LogoutHandler {


    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
        String tokenValue = null;

        if(token == null) {
            Cookie[] cookies = request.getCookies();
            if (cookies == null) {
                sendRedirect(response);
                return;
            }
        }


        //쿠키 제거
        Cookie cookie = new Cookie("o_id", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    private void sendRedirect(HttpServletResponse response) {
        try{
            response.sendRedirect("/");
        } catch (IOException e){
            throw new RuntimeException("로그아웃 도중 오류 발생", e);
        }
    }
}
