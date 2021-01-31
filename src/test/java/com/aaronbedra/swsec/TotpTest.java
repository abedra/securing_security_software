package com.aaronbedra.swsec;

import com.aaronbedra.swsec.Types.*;
import com.jnape.palatable.lambda.adt.Either;
import com.jnape.palatable.shoki.impl.StrictQueue;
import com.jnape.palatable.shoki.impl.StrictStack;
import org.junit.Test;

import static com.aaronbedra.swsec.OTP.otp6;
import static com.aaronbedra.swsec.TimeStep.timeStep30;
import static com.aaronbedra.swsec.Totp.generateInstance;
import static com.aaronbedra.swsec.Types.Counter.counter;
import static com.jnape.palatable.lambda.adt.Either.right;
import static com.jnape.palatable.lambda.functions.builtin.fn3.FoldLeft.foldLeft;
import static com.jnape.palatable.shoki.impl.StrictQueue.strictQueue;
import static com.jnape.palatable.shoki.impl.StrictStack.strictStack;
import static org.junit.Assert.assertEquals;

public class TotpTest {
    @Test
    public void endToEnd() {
        Seed seed = new Seed("3132333435363738393031323334353637383930");
        StrictStack<Counter> counters = strictStack(
                counter(new TimeStamp(59L), timeStep30()),
                counter(new TimeStamp(1111111109L), timeStep30()),
                counter(new TimeStamp(1111111111L), timeStep30()),
                counter(new TimeStamp(1234567890L), timeStep30()),
                counter(new TimeStamp(2000000000L), timeStep30()),
                counter(new TimeStamp(20000000000L), timeStep30()));

        StrictQueue<Either<Failure, TOTP>> expected = strictQueue(
                right(new TOTP("287082")),
                right(new TOTP("081804")),
                right(new TOTP("050471")),
                right(new TOTP("005924")),
                right(new TOTP("279037")),
                right(new TOTP("353130")));

        StrictQueue<Either<Failure, TOTP>> actual = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(otp6(), seed, value).unsafePerformIO()),
                strictQueue(),
                counters);

        assertEquals(expected, actual);
    }
}
