package com.aaronbedra.swsec;

import com.aaronbedra.swsec.Types.TOTP;
import com.aaronbedra.swsec.Types.Seed;
import com.jnape.palatable.lambda.io.IO;

import java.security.SecureRandom;

import static com.aaronbedra.swsec.Totp.generateInstance;
import static com.aaronbedra.swsec.Totp.generateSeed;

public class Main {
    public static void main(String[] args) {
        Seed seed = generateSeed(64)
                .<IO<Seed>>runReaderT(new SecureRandom())
                .unsafePerformIO();
        TOTP totp = generateInstance(seed);
        System.out.println(totp);
    }
}
