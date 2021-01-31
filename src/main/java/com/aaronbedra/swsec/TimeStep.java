package com.aaronbedra.swsec;

import com.jnape.palatable.lambda.adt.coproduct.CoProduct3;
import com.jnape.palatable.lambda.functions.Fn1;

public abstract class TimeStep implements CoProduct3<TimeStep.TimeStep30, TimeStep.TimeStep60, TimeStep.TimeStep90, TimeStep> {
    public abstract int value();

    public static TimeStep30 timeStep30() {
        return TimeStep30.INSTANCE;
    }

    public static TimeStep60 timeStep60() {
        return TimeStep60.INSTANCE;
    }

    public static TimeStep90 timeStep90() {
        return TimeStep90.INSTANCE;
    }

    public static class TimeStep30 extends TimeStep {
        public static TimeStep30 INSTANCE = new TimeStep30();

        private TimeStep30() {
        }

        @Override
        public <R> R match(Fn1<? super TimeStep30, ? extends R> aFn,
                           Fn1<? super TimeStep60, ? extends R> bFn,
                           Fn1<? super TimeStep90, ? extends R> cFn) {
            return aFn.apply(this);
        }

        @Override
        public int value() {
            return 30;
        }
    }

    public static class TimeStep60 extends TimeStep {
        public static TimeStep60 INSTANCE = new TimeStep60();

        private TimeStep60() {
        }

        @Override
        public <R> R match(Fn1<? super TimeStep30, ? extends R> aFn,
                           Fn1<? super TimeStep60, ? extends R> bFn,
                           Fn1<? super TimeStep90, ? extends R> cFn) {
            return bFn.apply(this);
        }

        @Override
        public int value() {
            return 60;
        }
    }

    public static class TimeStep90 extends TimeStep {
        public static TimeStep90 INSTANCE = new TimeStep90();

        private TimeStep90() {
        }

        @Override
        public <R> R match(Fn1<? super TimeStep30, ? extends R> aFn,
                           Fn1<? super TimeStep60, ? extends R> bFn,
                           Fn1<? super TimeStep90, ? extends R> cFn) {
            return cFn.apply(this);
        }

        @Override
        public int value() {
            return 90;
        }
    }
}
