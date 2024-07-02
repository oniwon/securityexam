package org.example.jwtexam.service;

import lombok.RequiredArgsConstructor;
import org.example.jwtexam.domain.RefreshToken;
import org.example.jwtexam.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional(readOnly = false)
    public RefreshToken addRefreshToken(RefreshToken refreshToken) {
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional(readOnly = true)
    public Optional<RefreshToken> findRefreshToken(String refreshToken) {
        return refreshTokenRepository.findByValue(refreshToken);
    }

    public void deleteRefreshToken(String refreshToken) {
        refreshTokenRepository.findByValue(refreshToken).ifPresent(refreshTokenRepository::delete);
    }
}
