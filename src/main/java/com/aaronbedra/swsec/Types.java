package com.aaronbedra.swsec;

import com.jnape.palatable.lambda.io.IO;

import static com.jnape.palatable.lambda.io.IO.io;

public final class Types {
    public static record Seed(String value) {}
    public static record TOTP(String value) {}
    public static record Counter(byte[] value) {}
    public static record HmacKey(byte[] value) {}
    public static record HmacMessage(byte[] value) {}
    public static record HmacResult(byte[] value) {}
    public static record HmacFailure(Throwable value) {}
    public static record TotpBinary(int value) {}
    public static record TimeStamp(long value) {
        public static IO<TimeStamp> now() {
            return io(() -> new TimeStamp(System.currentTimeMillis() / 1000));
        }
    }
}
