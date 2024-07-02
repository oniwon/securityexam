package org.example.jwtexam.dto;

import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
// 응답 객체 !
public class UserLoginResponseDto {
    private String accessToken;
    private String refreshToken;
    private Long userId;
    private String name;
}
