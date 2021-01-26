package com.aaronbedra.swsec;

import com.aaronbedra.swsec.Types.Seed;
import com.aaronbedra.swsec.Types.TimeStamp;
import com.aaronbedra.swsec.Types.TimeStep;
import com.jnape.palatable.lambda.io.IO;

import java.security.SecureRandom;

import static com.aaronbedra.swsec.OTP.otp6;
import static com.aaronbedra.swsec.Totp.*;
import static com.jnape.palatable.lambda.functions.builtin.fn2.Into.into;
import static com.jnape.palatable.lambda.functions.builtin.fn2.Tupler2.tupler;
import static com.jnape.palatable.lambda.io.IO.io;

public class Main {
    public static void main(String[] args) {
        generateSeed(64)
                .<IO<Seed>>runReaderT(new SecureRandom())
                .zip(io(() -> new TimeStamp(System.currentTimeMillis() / 1000)).fmap(tupler()))
                .flatMap(into((timeStamp, seed) -> generateInstance(otp6(), seed, counter(timeStamp, new TimeStep(30)))))
                .flatMap(failureOrTotp -> failureOrTotp.match(
                        hmacFailure -> io(() -> System.out.println(hmacFailure.value().getMessage())),
                        totp -> io(() -> System.out.println(totp))))
                .unsafePerformIO();
    }
}
