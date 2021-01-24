package com.aaronbedra.swsec;

import com.aaronbedra.swsec.Types.Counter;
import com.aaronbedra.swsec.Types.Seed;
import com.aaronbedra.swsec.Types.TOTP;
import com.jnape.palatable.shoki.impl.StrictQueue;
import com.jnape.palatable.shoki.impl.StrictStack;
import org.junit.Test;

import static com.aaronbedra.swsec.Totp.counterToBytes;
import static com.aaronbedra.swsec.Totp.generateInstance;
import static com.jnape.palatable.lambda.functions.builtin.fn3.FoldLeft.foldLeft;
import static com.jnape.palatable.lambda.io.IO.io;
import static com.jnape.palatable.shoki.impl.StrictQueue.strictQueue;
import static com.jnape.palatable.shoki.impl.StrictStack.strictStack;
import static org.junit.Assert.assertEquals;

public class TotpTest {
    @Test
    public void endToEnd() {
        Seed seed = new Seed("3132333435363738393031323334353637383930");
        StrictStack<Counter> counters = strictStack(
                new Counter(counterToBytes(59L)),
                new Counter(counterToBytes(1111111109L)),
                new Counter(counterToBytes(1111111111L)),
                new Counter(counterToBytes(1234567890L)),
                new Counter(counterToBytes(2000000000L)),
                new Counter(counterToBytes(20000000000L)));

        StrictQueue<TOTP> expected = strictQueue(
                new TOTP("287082"),
                new TOTP("081804"),
                new TOTP("050471"),
                new TOTP("005924"),
                new TOTP("279037"),
                new TOTP("353130"));

        StrictQueue<TOTP> actual = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(seed, io(() -> value)).unsafePerformIO()),
                strictQueue(),
                counters);

        assertEquals(expected, actual);
    }
}
