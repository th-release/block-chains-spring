package com.threlease.blockchain.functions.auth;

import com.threlease.blockchain.entites.AuthEntity;
import com.threlease.blockchain.enums.Roles;
import com.threlease.blockchain.functions.auth.dto.LoginDto;
import com.threlease.blockchain.functions.auth.dto.SignUpDto;
import com.threlease.blockchain.utils.GetRandom;
import com.threlease.blockchain.utils.StringUtil;
import com.threlease.blockchain.utils.responses.BasicResponse;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<Object> Login(
            @RequestBody LoginDto dto
    ) throws JoseException {
        Optional<AuthEntity> auth = authService.findOneByUsername(dto.getUsername());

        if (auth.isEmpty()) {
            BasicResponse response = BasicResponse.builder()
                    .success(false)
                    .message(Optional.of("유저를 찾을 수 없습니다."))
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        } else {
            AuthEntity user = auth.get();
            if (user.getPassword().equals(StringUtil.applySha512(dto.getPassword() + user.getSalt()))) {
                String accessToken = authService.tokenSign(user.getUuid());

                BasicResponse response = BasicResponse.builder()
                        .success(true)
                        .message(Optional.of("로그인 성공"))
                        .data(Optional.ofNullable(accessToken))
                        .build();
                return ResponseEntity.status(HttpStatus.CREATED).body(response);
            } else {
                BasicResponse response = BasicResponse.builder()
                        .success(false)
                        .message(Optional.of("아이디 혹은 비밀번호를 확인해주세요."))
                        .build();
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<Object> SignUp(
            @RequestBody SignUpDto dto
    ) {
        if (dto.getUsername() == null || dto.getUsername().trim().isEmpty()) {
            BasicResponse response = BasicResponse.builder()
                    .success(false)
                    .message(Optional.of("username을 입력해주세요."))
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        if (dto.getPassword() == null || dto.getPassword().trim().isEmpty()) {
            BasicResponse response = BasicResponse.builder()
                    .success(false)
                    .message(Optional.of("password를 입력해주세요."))
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        String salt = new GetRandom().run("all", 32);
        AuthEntity auth = AuthEntity.builder()
                .username(dto.getUsername())
                .password(StringUtil.applySha512(dto.getPassword() + salt))
                .salt(salt)
                .createdAt(LocalDateTime.now())
                .role(Roles.ROLE_USER)
                .build();

        Optional<AuthEntity> User = authService.findOneByUsername(dto.getUsername());
        try {
            if (User.isPresent()) throw new Exception("이미 다른 유저가 데이터베이스에 있습니다.");
        } catch (Exception e) {
            BasicResponse response = BasicResponse.builder()
                    .success(false)
                    .data(Optional.of(e.getMessage()))
                    .build();
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }

        authService.authSave(auth);

        Map<String, Object> result = new HashMap<>();
        result.put("uuid", auth.getUuid());
        result.put("username", auth.getUsername());
        BasicResponse response = BasicResponse.builder()
                .success(true)
                .message(Optional.of("정상적으로 회원가입이 완료되었습니다"))
                .data(Optional.of(result))
                .build();

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/@me")
    public ResponseEntity<Object> Me(
            @RequestHeader(value = "Authorization") String token
    ) throws JoseException, InvalidJwtException, MalformedClaimException {
        return authService.Me(token);
    }
}
