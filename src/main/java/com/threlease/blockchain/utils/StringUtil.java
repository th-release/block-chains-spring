package com.threlease.blockchain.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class StringUtil {
  public static String applySha512(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");

            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array to hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : messageDigest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            // Handle NoSuchAlgorithmException (unavailable algorithm)
            e.printStackTrace();
            return null;
        }
    }
    // SHA256을 적용하는 메소드
    public static String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // 적용하고 배열로 넘김
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            // 해시를 16진수로 변환
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        }
        catch(Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String hexToBinary(String hex) {
        // 16진수 문자열을 숫자로 변환합니다.
        BigInteger num = new BigInteger(hex, 16);
        // 숫자를 2진수 문자열로 변환합니다.
        return num.toString(2);
    }
}
