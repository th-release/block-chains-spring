package com.threlease.blockchain.functions.auth;

import com.threlease.blockchain.repositories.AuthRepository;
import com.threlease.blockchain.entites.AuthEntity;
import com.threlease.blockchain.utils.jsonwebtoken.JwtProvider;
import com.threlease.blockchain.utils.responses.BasicResponse;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.springframework.core.io.FileSystemResource;
import org.springframework.data.repository.query.Param;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.File;
import java.io.IOException;
import java.util.*;

@Service
public class AuthServiceImpl implements AuthService {
    private final AuthRepository authRepository;
    private final JwtProvider jwtProvider;

    public AuthServiceImpl(AuthRepository authRepository, JwtProvider jwtProvider) {
        this.authRepository = authRepository;
        this.jwtProvider = jwtProvider;
    }

    @Override
    public Optional<AuthEntity> findOneByUUID(@Param("uuid") String uuid) {
        return authRepository.findOneByUUID(uuid);
    }

    @Override
    public Optional<AuthEntity> findOneByUsername(@Param("username") String username) {
        return authRepository.findOneByUsername(username);
    }

    @Override
    public List<AuthEntity> findAllLimitOrderByCreatedAtDesc(@Param("limit") int limit) {
        return authRepository.findAllLimitOrderByCreatedAtDesc(limit);
    }

    @Override
    public void authSave(AuthEntity auth) {
        authRepository.save(auth);
    }

    @Override
    public String tokenSign(String uuid) throws JoseException {
        return jwtProvider.sign(uuid);
    }

    public ResponseEntity<Object> Me(
            @RequestHeader(value = "Authorization") String token
    ) throws JoseException, InvalidJwtException, MalformedClaimException {
        Optional<AuthEntity> data = jwtProvider.findByToken(token);

        if (data.isPresent()) {
            AuthEntity _data = data.get();
            _data
                .setPassword("unknown");
            _data
                .setSalt("unknown");
            data = Optional.of(_data);
        }
        System.out.println(jwtProvider.verify(token));
        BasicResponse response = BasicResponse.builder()
                .success(true)
                .message(Optional.empty())
                .data(Optional.of(data))
                .build();

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
