package com.aaronbedra.swsec;

import com.aaronbedra.swsec.Totp.HmacKey;
import com.aaronbedra.swsec.Totp.HmacMessage;
import com.aaronbedra.swsec.Types.Failure;
import com.jnape.palatable.lambda.adt.Either;
import com.jnape.palatable.lambda.adt.coproduct.CoProduct3;
import com.jnape.palatable.lambda.functions.Fn1;
import com.jnape.palatable.lambda.io.IO;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static com.jnape.palatable.lambda.adt.Either.*;
import static com.jnape.palatable.lambda.functions.builtin.fn1.Constantly.constantly;
import static com.jnape.palatable.lambda.io.IO.io;

public abstract class HMac implements CoProduct3<HMac.HMacSHA1, HMac.HMacSHA256, HMac.HMacSHA512, HMac> {
    public static record HmacResult(byte[] value) {
    }

    public abstract IO<Mac> getInstance();

    public IO<Either<Failure, HmacResult>> hash(HmacKey key, HmacMessage message) {
        return getInstance()
                .flatMap(hmac -> io(() -> new SecretKeySpec(key.value(), "RAW"))
                        .flatMap(secretKeySpec -> io(() -> hmac.init(secretKeySpec)))
                        .flatMap(constantly(io(() -> Either.<Failure, HmacResult>right(new HmacResult(hmac.doFinal(message.value())))))))
                .catchError(throwable -> io(left(new Failure(throwable))));
    }

    public static HMacSHA1 hMacSHA1() {
        return HMacSHA1.INSTANCE;
    }

    public static HMacSHA256 hMacSHA256() {
        return HMacSHA256.INSTANCE;
    }

    public static HMacSHA512 hMacSHA512() {
        return HMacSHA512.INSTANCE;
    }

    public static final class HMacSHA1 extends HMac {
        public static final HMacSHA1 INSTANCE = new HMacSHA1();

        private HMacSHA1() {
        }

        @Override
        public <R> R match(Fn1<? super HMacSHA1, ? extends R> aFn,
                           Fn1<? super HMacSHA256, ? extends R> bFn,
                           Fn1<? super HMacSHA512, ? extends R> cFn) {
            return aFn.apply(this);
        }

        @Override
        public IO<Mac> getInstance() {
            return io(() -> Mac.getInstance("HmacSHA1"));
        }
    }

    public static final class HMacSHA256 extends HMac {
        public static final HMacSHA256 INSTANCE = new HMacSHA256();

        private HMacSHA256() {
        }

        @Override
        public <R> R match(Fn1<? super HMacSHA1, ? extends R> aFn,
                           Fn1<? super HMacSHA256, ? extends R> bFn,
                           Fn1<? super HMacSHA512, ? extends R> cFn) {
            return bFn.apply(this);
        }

        @Override
        public IO<Mac> getInstance() {
            return io(() -> Mac.getInstance("HmacSHA256"));
        }
    }

    public static final class HMacSHA512 extends HMac {
        public static final HMacSHA512 INSTANCE = new HMacSHA512();

        private HMacSHA512() {
        }

        @Override
        public <R> R match(Fn1<? super HMacSHA1, ? extends R> aFn,
                           Fn1<? super HMacSHA256, ? extends R> bFn,
                           Fn1<? super HMacSHA512, ? extends R> cFn) {
            return cFn.apply(this);
        }

        @Override
        public IO<Mac> getInstance() {
            return io(() -> Mac.getInstance("HmacSHA512"));
        }
    }
}
