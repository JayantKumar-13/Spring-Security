package com.Security_demo.SpringSecdemo.handlers;

import com.Security_demo.SpringSecdemo.entities.User;
import com.Security_demo.SpringSecdemo.service.JwtService;
import com.Security_demo.SpringSecdemo.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserService userService;

    @Value("${deploy.env}")
    private String deployEnv;

    private final JwtService jwtService;

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        DefaultOAuth2User oAuth2User = (DefaultOAuth2User) token.getPrincipal();             // Gets the authenticated user’s details (name, email) from Google.

        String email = oAuth2User.getAttribute("email");
        User user = userService.getUsrByEmail(email);
        if(user == null){                  // If the user doesn’t exist in your DB, create and save them.
            User newUser = User.builder()
                    .name(oAuth2User.getAttribute("name"))
                    .email(email)
                    .build();
            user = userService.save(newUser);
        }

        String accessToken = jwtService.generateAccessToken(user);
        String refrehToken = jwtService.generateRefreshToken(user);

        Cookie cookie = new Cookie("refreshToken", refrehToken);
        // Saves refresh token in an HttpOnly cookie (prevents JavaScript from stealing it).

        //Uses the ${deploy.env} property to check if environment = production (so local dev isn’t strict).

        cookie.setHttpOnly("production".equals(deployEnv));
        response.addCookie(cookie);

        String frontEndUrl = "http://localhost:8080/home.html?token="+accessToken;   // Redirects to your frontend with the access token in the query string

        //getRedirectStrategy().sendRedirect(request ,response , frontEndUrl);
        //response.sendRedirect(frontEndUrl);

        //This ties OAuth login → User DB → JWT system → Session tracking → Redirect to frontend.
    }

}
