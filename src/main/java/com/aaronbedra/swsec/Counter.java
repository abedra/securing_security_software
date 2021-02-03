package com.aaronbedra.swsec;

public record Counter(byte[] value) {
    public static Counter counter(TimeStamp timeStamp, TimeStep timeStep) {
        long counter = timeStamp.value() / timeStep.value();
        byte[] buffer = new byte[Long.SIZE / Byte.SIZE];
        for (int i = 7; i >= 0; i--) {
            buffer[i] = (byte) (counter & 0xff);
            counter = counter >> 8;
        }
        return new Counter(buffer);
    }
}
