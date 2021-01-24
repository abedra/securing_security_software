package com.aaronbedra.swsec;

import org.junit.Test;

import static com.aaronbedra.swsec.Totp.counterToBytes;
import static com.aaronbedra.swsec.Totp.generateInstance;
import static org.junit.Assert.assertEquals;

public class TotpTest {
    @Test
    public void endToEnd() {
        String seed = "3132333435363738393031323334353637383930";
        long[] times =             {59L,      1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] expectedOutputs = {"287082", "081804",    "050471",    "005924",    "279037",    "353130"};
        for (int i = 0; i < times.length; i++) {
            assertEquals(expectedOutputs[i], generateInstance(seed, counterToBytes(times[i])));
        }
    }
}
