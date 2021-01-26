package com.aaronbedra.swsec;

public final class Types {
    public static record Seed(String value) {}
    public static record TOTP(String value) {}
    public static record Counter(byte[] value) {}
    public static record HmacKey(byte[] value) {}
    public static record HmacMessage(byte[] value) {}
    public static record HmacResult(byte[] value) {}
    public static record HmacFailure(Throwable value) {}
    public static record TotpBinary(int value) {}
    public static record TimeStep(int value) {}
    public static record TimeStamp(long value) {}
}
