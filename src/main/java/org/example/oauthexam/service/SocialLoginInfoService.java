package org.example.oauthexam.service;

import lombok.RequiredArgsConstructor;
import org.example.oauthexam.domain.SocialLoginInfo;
import org.example.oauthexam.repository.SocialLoginInfoRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class SocialLoginInfoService {
    private final SocialLoginInfoRepository socialLoginInfoRepository;

    @Transactional(readOnly = false)
    public SocialLoginInfo saveSocialLoginInfo(String provider, String socialId){
        SocialLoginInfo socialLoginInfo = new SocialLoginInfo();
        socialLoginInfo.setProvider(provider);
        socialLoginInfo.setSocialId(socialId);

        return socialLoginInfoRepository.save(socialLoginInfo);
    }

    @Transactional(readOnly = true)
    public Optional<SocialLoginInfo> findByProviderAndUuidAndSocialId(String provider, String uuid, String socialId){
        return socialLoginInfoRepository.findByProviderAndUuidAndSocialId(provider, uuid, socialId);
    }
}