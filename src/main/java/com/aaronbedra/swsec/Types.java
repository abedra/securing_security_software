package com.aaronbedra.swsec;

import com.jnape.palatable.lambda.io.IO;
import com.jnape.palatable.lambda.monad.transformer.builtin.ReaderT;

import java.security.SecureRandom;

import static com.jnape.palatable.lambda.io.IO.io;
import static com.jnape.palatable.lambda.monad.transformer.builtin.ReaderT.readerT;
import static org.apache.commons.codec.binary.Hex.encodeHexString;

public final class Types {
    public static record Failure(Throwable value) {}

    public static record Seed(String value) {
        public static ReaderT<SecureRandom, IO<?>, Seed> generateSeed(int length) {
            return readerT(secureRandom -> io(() -> {
                byte[] randomBytes = new byte[length];
                secureRandom.nextBytes(randomBytes);
                return new Seed(encodeHexString(randomBytes));
            }));
        }
    }

    public static record Counter(byte[] value) {
        public static Counter counter(TimeStamp timeStamp, TimeStep timeStep) {
            long counter = timeStamp.value() / timeStep.value();
            byte[] buffer = new byte[Long.SIZE / Byte.SIZE];
            for (int i = 7; i >= 0; i--) {
                buffer[i] = (byte) (counter & 0xff);
                counter = counter >> 8;
            }
            return new Counter(buffer);
        }
    }

    public static record TimeStamp(long value) {
        public static IO<TimeStamp> now() {
            return io(() -> new TimeStamp(System.currentTimeMillis() / 1000));
        }
    }
}
