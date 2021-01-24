package com.aaronbedra.swsec;

public final class Types {
    public static record Seed(String value) {}
    public static record TOTP(String value) {}
    public static record Counter(byte[] value) {}
}
