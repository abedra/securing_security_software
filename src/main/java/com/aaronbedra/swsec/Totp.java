package com.aaronbedra.swsec;

import com.aaronbedra.swsec.Types.*;
import com.jnape.palatable.lambda.adt.Either;
import com.jnape.palatable.lambda.io.IO;
import com.jnape.palatable.lambda.monad.transformer.builtin.ReaderT;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;

import static com.jnape.palatable.lambda.adt.Either.trying;
import static com.jnape.palatable.lambda.io.IO.io;
import static com.jnape.palatable.lambda.monad.transformer.builtin.ReaderT.readerT;
import static org.apache.commons.codec.binary.Hex.encodeHexString;

public final class Totp {
    private Totp() {
    }

    public static ReaderT<SecureRandom, IO<?>, Seed> generateSeed(int length) {
        return readerT(secureRandom -> io(() -> {
            byte[] randomBytes = new byte[length];
            secureRandom.nextBytes(randomBytes);
            return new Seed(encodeHexString(randomBytes));
        }));
    }

    public static IO<Either<HmacFailure, TOTP>> generateInstance(OTP otp, Seed seed, Counter counter) {
        return hash(hmacKey(seed), new HmacMessage(counter.value()))
                .fmap(eitherFailureHmacResult -> eitherFailureHmacResult
                        .biMapR(hmacResult -> buildTotp(calculateTotp(hmacResult), otp)));
    }

    private static TotpBinary calculateTotp(HmacResult hmacResult) {
        byte[] result = hmacResult.value();
        int offset = result[result.length - 1] & 0xf;
        return new TotpBinary(((result[offset] & 0x7f) << 24) |
                ((result[offset + 1] & 0xff) << 16) |
                ((result[offset + 2] & 0xff) << 8) |
                ((result[offset + 3] & 0xff)));
    }

    private static TOTP buildTotp(TotpBinary totpBinary, OTP otp) {
        StringBuilder code = new StringBuilder(Integer.toString(totpBinary.value() % otp.power().value()));
        while (code.length() < otp.digits().value()) {
            code.insert(0, "0");
        }
        return new TOTP(code.toString());
    }

    public static Counter counter(TimeStamp timeStamp, TimeStep timeStep) {
        long counter = timeStamp.value() / timeStep.value();
        byte[] buffer = new byte[Long.SIZE / Byte.SIZE];
        for (int i = 7; i >= 0; i--) {
            buffer[i] = (byte) (counter & 0xff);
            counter = counter >> 8;
        }
        return new Counter(buffer);
    }

    private static HmacKey hmacKey(Seed seed) {
        byte[] bArray = new BigInteger("10" + seed.value(), 16).toByteArray();
        byte[] ret = new byte[bArray.length - 1];
        if (ret.length >= 0) {
            System.arraycopy(bArray, 1, ret, 0, ret.length);
        }
        return new HmacKey(ret);
    }

    private static IO<Either<HmacFailure, HmacResult>> hash(HmacKey key, HmacMessage message) {
        return io(() -> trying(() -> {
            Mac hmac = Mac.getInstance("HmacSHA1");
            SecretKeySpec keySpec = new SecretKeySpec(key.value(), "RAW");
            hmac.init(keySpec);
            return new HmacResult(hmac.doFinal(message.value()));
        }, HmacFailure::new));
    }
}