package com.Security_demo.SpringSecdemo.Controller;

import com.Security_demo.SpringSecdemo.dto.LoginDto;
import com.Security_demo.SpringSecdemo.dto.LoginResponseDto;
import com.Security_demo.SpringSecdemo.dto.SignupDto;
import com.Security_demo.SpringSecdemo.dto.UserDto;
import com.Security_demo.SpringSecdemo.service.AuthService;
import com.Security_demo.SpringSecdemo.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
     private final UserService userService;
     private final AuthService authService;

     @Value("${deploy.env}")
     private String deployEnv;

     @PostMapping("/signup")
     public ResponseEntity<UserDto> signup(@RequestBody SignupDto signupDto){
          UserDto userDto = userService.signUp(signupDto);
          return ResponseEntity.ok(userDto);
     }

     @PostMapping("/login")
     public ResponseEntity<LoginResponseDto> login(@RequestBody LoginDto loginDto, HttpServletRequest request,HttpServletResponse response) {
          LoginResponseDto loginResponseDto = authService.login(loginDto);
          Cookie cookie = new Cookie("refreshToken", loginResponseDto.getRefreshToken());
          cookie.setHttpOnly(true);
          response.addCookie(cookie);
          return ResponseEntity.ok(loginResponseDto);
     }
}
