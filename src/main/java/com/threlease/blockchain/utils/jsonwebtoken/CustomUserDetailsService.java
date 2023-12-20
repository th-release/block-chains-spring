package com.threlease.blockchain.utils.jsonwebtoken;

import com.threlease.blockchain.entites.AuthEntity;
import com.threlease.blockchain.repositories.AuthRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final AuthRepository authRepository;

    @Override
    public UserDetails loadUserByUsername(String uuid) throws UsernameNotFoundException {
        Optional<AuthEntity> member = authRepository.findOneByUUID(uuid);
            member
                .orElseThrow(() -> new UsernameNotFoundException("User not found in the database"));

        return new CustomUserDetails(member.get());
    }
}
