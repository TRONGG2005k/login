package com.example.test_user.response;


import lombok.*;
import lombok.experimental.FieldDefaults;


@FieldDefaults(level = AccessLevel.PRIVATE)
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ErrorResponse {
        int status;
        String message;
        Long timestamp;
}

