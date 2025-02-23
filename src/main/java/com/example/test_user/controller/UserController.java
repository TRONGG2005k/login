package com.example.test_user.controller;

import com.example.test_user.dto.CreateUserDto;
import com.example.test_user.dto.UpdateUserDto;
import com.example.test_user.entity.User;
import com.example.test_user.response.ApiResponse;
import com.example.test_user.response.UserResponse;
import com.example.test_user.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ApiResponse<User> registerUser(@RequestBody CreateUserDto request) {
        User user = userService.register(request);
        return ApiResponse.<User>builder()
                .data(user)
                .message("register success")
                .success(true)
                .build();
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<User>>> getAllUsers() {
        List<User> users = userService.getAllUser();
        return ResponseEntity.ok(new ApiResponse<>(true, "Users retrieved successfully", users));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<User>> getUserById(@PathVariable String id) {
        User user = userService.getById(id);
        return ResponseEntity.ok(new ApiResponse<>(true, "User retrieved successfully", user));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<User>> updateUser(@PathVariable String id, @RequestBody UpdateUserDto request) {
        User user = userService.updateUser(id, request);
        return ResponseEntity.ok(new ApiResponse<>(true, "User updated successfully", user));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<String>> deleteUser(@PathVariable String id) {
        String message = userService.delete(id);
        return ResponseEntity.ok(new ApiResponse<>(true, message, null));
    }

    @GetMapping("/myInfo")
     // ✅ Chỉ user đã đăng nhập mới gọi được
    public UserResponse getMyInfo() {
        return userService.getMyInfo();
    }

}