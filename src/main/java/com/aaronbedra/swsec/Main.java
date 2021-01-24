package com.aaronbedra.swsec;

public class Main {
    public static void main(String[] args) {
        String seed = Totp.generateSeed();
        String instance = Totp.generateInstance(seed);
        System.out.println(instance);
    }
}
