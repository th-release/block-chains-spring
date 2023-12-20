package com.threlease.blockchain.functions.auth.dto;

import lombok.Data;
import lombok.Getter;

@Data
@Getter
public class LoginDto {
    private String username;
    private String password;
}
