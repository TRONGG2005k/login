package com.example.test_user.response;


import lombok.*;
import lombok.experimental.FieldDefaults;

@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@NoArgsConstructor
@Data
@Builder
public class UserResponse {
    String userName;
    String role;
    String email;
}
