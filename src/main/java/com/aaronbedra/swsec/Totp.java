package com.aaronbedra.swsec;

import com.aaronbedra.swsec.HMac.HmacResult;
import com.aaronbedra.swsec.Types.Counter;
import com.aaronbedra.swsec.Types.Failure;
import com.aaronbedra.swsec.Types.Seed;
import com.aaronbedra.swsec.Types.TOTP;
import com.jnape.palatable.lambda.adt.Either;
import com.jnape.palatable.lambda.io.IO;

import java.math.BigInteger;

public final class Totp {
    private static record TotpBinary(int value) {}
    public static record HmacKey(byte[] value) {}
    public static record HmacMessage(byte[] value) {}

    private Totp() {
    }

    public static IO<Either<Failure, TOTP>> generateInstance(OTP otp, HMac hMac, Seed seed, Counter counter) {
        return hMac.hash(hmacKey(seed), new HmacMessage(counter.value()))
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

    private static HmacKey hmacKey(Seed seed) {
        byte[] bArray = new BigInteger("10" + seed.value(), 16).toByteArray();
        byte[] ret = new byte[bArray.length - 1];
        if (ret.length >= 0) {
            System.arraycopy(bArray, 1, ret, 0, ret.length);
        }
        return new HmacKey(ret);
    }
}