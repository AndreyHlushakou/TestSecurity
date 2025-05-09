package com.example.testsecurity.dto;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@AllArgsConstructor
public class TokenResponseDto {
    final String type = "Bearer";
    String accessToken;
    String refreshToken;
}
