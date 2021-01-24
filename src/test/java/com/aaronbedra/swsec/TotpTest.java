package com.aaronbedra.swsec;

import com.aaronbedra.swsec.Types.TOTP;
import com.aaronbedra.swsec.Types.Seed;
import org.junit.Test;

import static com.aaronbedra.swsec.Totp.counterToBytes;
import static com.aaronbedra.swsec.Totp.generateInstance;
import static org.junit.Assert.assertEquals;

public class TotpTest {
    @Test
    public void endToEnd() {
        Seed seed = new Seed("3132333435363738393031323334353637383930");
        long[] times = {
                59L,
                1111111109L,
                1111111111L,
                1234567890L,
                2000000000L,
                20000000000L
        };
        Types.TOTP[] expectedOutputs = {
                new TOTP("287082"),
                new Types.TOTP("081804"),
                new Types.TOTP("050471"),
                new Types.TOTP("005924"),
                new Types.TOTP("279037"),
                new Types.TOTP("353130")
        };
        for (int i = 0; i < times.length; i++) {
            assertEquals(expectedOutputs[i], generateInstance(seed, counterToBytes(times[i])));
        }
    }
}
