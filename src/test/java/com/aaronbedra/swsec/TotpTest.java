package com.aaronbedra.swsec;

import com.jnape.palatable.lambda.adt.Either;
import com.jnape.palatable.shoki.impl.StrictQueue;
import com.jnape.palatable.shoki.impl.StrictStack;
import org.junit.Test;

import static com.aaronbedra.swsec.HMac.*;
import static com.aaronbedra.swsec.OTP.otp6;
import static com.aaronbedra.swsec.OTP.otp8;
import static com.aaronbedra.swsec.TimeStep.timeStep30;
import static com.aaronbedra.swsec.Totp.generateInstance;
import static com.aaronbedra.swsec.Counter.counter;
import static com.jnape.palatable.lambda.adt.Either.right;
import static com.jnape.palatable.lambda.functions.builtin.fn3.FoldLeft.foldLeft;
import static com.jnape.palatable.shoki.impl.StrictQueue.strictQueue;
import static com.jnape.palatable.shoki.impl.StrictStack.strictStack;
import static org.junit.Assert.assertEquals;

public class TotpTest {
    @Test
    public void rfc6238() {
        Seed seed = new Seed("3132333435363738393031323334353637383930");
        Seed seed32 = new Seed("3132333435363738393031323334353637383930313233343536373839303132");
        Seed seed64 = new Seed("31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334");

        StrictStack<Counter> counters = strictStack(
                counter(new TimeStamp(59L), timeStep30()),
                counter(new TimeStamp(1111111109L), timeStep30()),
                counter(new TimeStamp(1111111111L), timeStep30()),
                counter(new TimeStamp(1234567890L), timeStep30()),
                counter(new TimeStamp(2000000000L), timeStep30()),
                counter(new TimeStamp(20000000000L), timeStep30()));


        StrictQueue<Either<Failure, Totp>> expectedSha1 = strictQueue(
                right(new Totp("94287082")),
                right(new Totp("07081804")),
                right(new Totp("14050471")),
                right(new Totp("89005924")),
                right(new Totp("69279037")),
                right(new Totp("65353130")));

        StrictQueue<Either<Failure, Totp>> expectedSha256 = strictQueue(
                right(new Totp("46119246")),
                right(new Totp("68084774")),
                right(new Totp("67062674")),
                right(new Totp("91819424")),
                right(new Totp("90698825")),
                right(new Totp("77737706")));

        StrictQueue<Either<Failure, Totp>> expectedSha512 = strictQueue(
                right(new Totp("90693936")),
                right(new Totp("25091201")),
                right(new Totp("99943326")),
                right(new Totp("93441116")),
                right(new Totp("38618901")),
                right(new Totp("47863826")));

        StrictQueue<Either<Failure, Totp>> actualSha1 = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(otp8(), hMacSHA1(), seed, value).unsafePerformIO()),
                strictQueue(),
                counters);

        StrictQueue<Either<Failure, Totp>> actualSha256 = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(otp8(), hMacSHA256(), seed32, value).unsafePerformIO()),
                strictQueue(),
                counters);

        StrictQueue<Either<Failure, Totp>> actualSha512 = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(otp8(), hMacSHA512(), seed64, value).unsafePerformIO()),
                strictQueue(),
                counters);

        assertEquals(expectedSha1, actualSha1);
        assertEquals(expectedSha256, actualSha256);
        assertEquals(expectedSha512, actualSha512);

    }

    @Test
    public void googleAuthenticator() {
        Seed seed = new Seed("3132333435363738393031323334353637383930");
        StrictStack<Counter> counters = strictStack(
                counter(new TimeStamp(59L), timeStep30()),
                counter(new TimeStamp(1111111109L), timeStep30()),
                counter(new TimeStamp(1111111111L), timeStep30()),
                counter(new TimeStamp(1234567890L), timeStep30()),
                counter(new TimeStamp(2000000000L), timeStep30()),
                counter(new TimeStamp(20000000000L), timeStep30()));

        StrictQueue<Either<Failure, Totp>> expected = strictQueue(
                right(new Totp("287082")),
                right(new Totp("081804")),
                right(new Totp("050471")),
                right(new Totp("005924")),
                right(new Totp("279037")),
                right(new Totp("353130")));

        StrictQueue<Either<Failure, Totp>> actual = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(otp6(), hMacSHA1(), seed, value).unsafePerformIO()),
                strictQueue(),
                counters);

        assertEquals(expected, actual);
    }
}
