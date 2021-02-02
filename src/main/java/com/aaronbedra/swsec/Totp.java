package com.aaronbedra.swsec;

import com.aaronbedra.swsec.HMac.HmacResult;
import com.aaronbedra.swsec.Types.Counter;
import com.aaronbedra.swsec.Types.Failure;
import com.aaronbedra.swsec.Types.Seed;
import com.aaronbedra.swsec.Types.TOTP;
import com.jnape.palatable.lambda.adt.Either;
import com.jnape.palatable.lambda.io.IO;

public final class Totp {
    private static record TotpBinary(int value) {
    }

    private Totp() {
    }

    public static IO<Either<Failure, TOTP>> generateInstance(OTP otp, HMac hMac, Seed seed, Counter counter) {
        return hMac.hash(seed, counter)
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
        String code = Integer.toString(totpBinary.value() % otp.power().value());
        int length = otp.digits().value() - code.length();

        return length > 0
                ? new TOTP("0".repeat(length) + code)
                : new TOTP(code);
    }
}