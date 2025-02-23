package com.example.test_user.service;


import com.example.test_user.dto.CreateUserDto;
import com.example.test_user.dto.UpdateUserDto;
import com.example.test_user.entity.User;
import com.example.test_user.repository.UserRepository;
import com.example.test_user.response.UserResponse;
import com.nimbusds.jose.JWSObject;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
    public User register(CreateUserDto request) {
        return userRepository.save(User.builder()
                        .email(request.getEmail())
                        .role("ROLE_USER")
                        .userName(request.getUserName())
                        .password(passwordEncoder.encode(request.getPassword()))
                .build());
    }
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getAllUser() {
        return userRepository.findAll();
    }

    public User getById(String id) {
        var user = userRepository.findById(id).orElseThrow(() -> new RuntimeException("user not found"));
        return user;
    }

    public User updateUser(String id, UpdateUserDto request) {
        var user = userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found!"));
        user.setUserName(request.getUserName());
        user.setPassword(request.getPassword());
        user.setEmail(request.getEmail());
        return userRepository.save(user);
    }
    @PreAuthorize("hasRole('ADMIN')")
    public String delete(String id) {
        userRepository.deleteById(id);
        return "đã xoá user";
    }

    public UserResponse getMyInfo() {
        var context = SecurityContextHolder.getContext();
        String name = context.getAuthentication().getName();
        log.info("name:" + name);
        User user = userRepository.findByUserName(name).orElseThrow(() -> new RuntimeException("user không tồn tại"));
        return UserResponse.builder()
                .email(user.getEmail())
                .userName(user.getUserName())
                .role(user.getRole())
                .build();
    }
}
