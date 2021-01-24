package com.aaronbedra.swsec;

import com.aaronbedra.swsec.Types.Counter;
import com.aaronbedra.swsec.Types.Seed;
import com.jnape.palatable.lambda.io.IO;

import java.security.SecureRandom;

import static com.aaronbedra.swsec.Totp.*;
import static com.jnape.palatable.lambda.io.IO.io;

public class Main {
    public static void main(String[] args) {
        generateSeed(64)
                .<IO<Seed>>runReaderT(new SecureRandom())
                .flatMap(seed -> generateInstance(seed, io(() -> new Counter(counterToBytes(System.currentTimeMillis() / 1000)))))
                .flatMap(totp -> io(() -> System.out.println(totp)))
                .unsafePerformIO();
    }
}
