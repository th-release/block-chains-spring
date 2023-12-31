package com.threlease.blockchain;

public class Config {
    /*
     * 난이도 조정 블록 범위
     */
    public static long DIFFICULTY_ADJUSTMENT_INTERVAL = 10;

    /*
     * 블록 생성 시간 (단위: 분) // 10 * 60 = 600
     */
    public static long BLOCK_GENERATION_INTERVAL = 10;

    /*
     * 생성 시간의 단위 (초)
     */
    public static long BLOCK_GENERATION_TIME_UNIT = 60;
}
