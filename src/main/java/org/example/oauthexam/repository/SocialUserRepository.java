package org.example.oauthexam.repository;

import org.example.oauthexam.domain.SocialUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SocialUserRepository extends JpaRepository<SocialUser,Long> {

    Optional<SocialUser> findBySocialIdAndProvider(String socialId, String provider);
}