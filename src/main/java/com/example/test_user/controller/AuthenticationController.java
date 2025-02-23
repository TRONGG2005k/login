package com.example.test_user.controller;


import com.example.test_user.dto.IntrospectsDto;
import com.example.test_user.dto.LoginRequestDto;
import com.example.test_user.dto.LogoutRequestDto;
import com.example.test_user.response.ApiResponse;
import com.example.test_user.response.LoginResponse;
import com.example.test_user.response.UserResponse;
import com.example.test_user.service.AuthenticationService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    @Autowired
    private AuthenticationService authenticationService;

    @SuppressWarnings("rawtypes")
    @PostMapping("/login")
    ApiResponse<LoginResponse> login(@RequestBody LoginRequestDto request, HttpServletResponse response) {
        var response1 = authenticationService.login(request, response);
        return ApiResponse.<LoginResponse>builder()
                .success(true)
                .message("success")
                .data(response1)
                .build();
    }

    @SuppressWarnings("rawtypes")
    @PostMapping("/introspects")
    ApiResponse introspects(@RequestBody IntrospectsDto token) {
        return ApiResponse.builder()
                .success(true)
                .message("success")
                .data(authenticationService.introspects(token.getToken()))
                .build();
    }

    
    @PostMapping("/logout")
    ApiResponse<String> logout(@RequestBody LogoutRequestDto request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        String result = authenticationService.logout(request, httpRequest, httpResponse);
        return ApiResponse.<String>builder()
                .success(true)
                .message("success")
                .data(result)
                .build();
    }

    @PostMapping("/refresh-token")
    ApiResponse<LoginResponse<UserResponse>> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        var response1 = authenticationService.refreshToken(request, response);
        System.out.println("📌 Backend nhận yêu cầu refresh token từ frontend");
        return ApiResponse.<LoginResponse<UserResponse>>builder()
                .success(true)
                .message("success")
                .data(response1)
                .build();
    }
}
