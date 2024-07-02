package org.example.jwtexam.security.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
// dto로 유효성 검사 !
public class UserLoginDto {
    @NotEmpty
    private String username;

    @NotEmpty
//    @Pattern(regexp=  "^(?=.*[a-zA-Z])(?=.*\\d)(?=.*\\W).{8,20}$")
    private String password;
}
