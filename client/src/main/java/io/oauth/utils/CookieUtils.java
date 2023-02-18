package io.oauth.utils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CookieUtils {

    public static void deleteCookies(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if(cookies == null) return;
        for (Cookie cookie : cookies) {
            Cookie cookieForDelete = new Cookie(cookie.getName(), null);
            cookieForDelete.setMaxAge(0);
            response.addCookie(cookieForDelete);
        }
    }

}
