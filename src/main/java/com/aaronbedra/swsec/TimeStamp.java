package com.aaronbedra.swsec;

import com.jnape.palatable.lambda.io.IO;

import static com.jnape.palatable.lambda.io.IO.io;

public record TimeStamp(long value) {
    public static IO<TimeStamp> now() {
        return io(() -> new TimeStamp(System.currentTimeMillis() / 1000));
    }
}
