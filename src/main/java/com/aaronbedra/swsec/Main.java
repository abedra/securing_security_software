package com.aaronbedra.swsec;

import com.aaronbedra.swsec.Types.TOTP;
import com.aaronbedra.swsec.Types.Seed;

import static com.aaronbedra.swsec.Totp.generateInstance;

public class Main {
    public static void main(String[] args) {
        Seed seed = Totp.generateSeed();
        TOTP totp = generateInstance(seed);
        System.out.println(totp);
    }
}
