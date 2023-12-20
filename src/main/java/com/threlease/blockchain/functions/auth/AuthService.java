package com.threlease.blockchain.functions.auth;

import com.threlease.blockchain.entites.AuthEntity;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.springframework.data.repository.query.Param;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
@Service
public interface AuthService {
    public Optional<AuthEntity> findOneByUUID(@Param("uuid") String uuid);
    Optional<AuthEntity> findOneByUsername(@Param("username") String username);
    List<AuthEntity> findAllLimitOrderByCreatedAtDesc(@Param("limit") int limit);
    void authSave(AuthEntity auth);
    String tokenSign(String uuid) throws JoseException;
    ResponseEntity<Object> Me(@RequestHeader(value = "Authorization") String token) throws JoseException, InvalidJwtException, MalformedClaimException;
}
