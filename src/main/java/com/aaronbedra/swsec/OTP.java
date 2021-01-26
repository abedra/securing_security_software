package com.aaronbedra.swsec;

import com.jnape.palatable.lambda.adt.coproduct.CoProduct8;
import com.jnape.palatable.lambda.functions.Fn1;

public abstract class OTP implements CoProduct8<OTP.OTP1, OTP.OTP2, OTP.OTP3, OTP.OTP4, OTP.OTP5, OTP.OTP6, OTP.OTP7, OTP.OTP8, OTP> {
    public static record Digits(int value) {}
    public static record Power(int value) {}

    public abstract Digits digits();
    public abstract Power power();

    public static OTP1 otp1() {
        return OTP1.INSTANCE;
    }

    public static OTP2 otp2() {
        return OTP2.INSTANCE;
    }

    public static OTP3 otp3() {
        return OTP3.INSTANCE;
    }

    public static OTP4 otp4() {
        return OTP4.INSTANCE;
    }

    public static OTP5 otp5() {
        return OTP5.INSTANCE;
    }

    public static OTP6 otp6() {
        return OTP6.INSTANCE;
    }

    public static OTP7 otp7() {
        return OTP7.INSTANCE;
    }

    public static OTP8 otp8() {
        return OTP8.INSTANCE;
    }

    public static class OTP1 extends OTP {
        public static OTP1 INSTANCE = new OTP1();

        private OTP1() {}

        @Override
        public <R> R match(Fn1<? super OTP1, ? extends R> aFn,
                           Fn1<? super OTP2, ? extends R> bFn,
                           Fn1<? super OTP3, ? extends R> cFn,
                           Fn1<? super OTP4, ? extends R> dFn,
                           Fn1<? super OTP5, ? extends R> eFn,
                           Fn1<? super OTP6, ? extends R> fFn,
                           Fn1<? super OTP7, ? extends R> gFn,
                           Fn1<? super OTP8, ? extends R> hFn) {
            return aFn.apply(this);
        }

        @Override
        public Digits digits() {
            return new Digits(1);
        }

        @Override
        public Power power() {
            return new Power(10);
        }
    }

    public static class OTP2 extends OTP {
        public static OTP2 INSTANCE = new OTP2();

        private OTP2() {}

        @Override
        public <R> R match(Fn1<? super OTP1, ? extends R> aFn,
                           Fn1<? super OTP2, ? extends R> bFn,
                           Fn1<? super OTP3, ? extends R> cFn,
                           Fn1<? super OTP4, ? extends R> dFn,
                           Fn1<? super OTP5, ? extends R> eFn,
                           Fn1<? super OTP6, ? extends R> fFn,
                           Fn1<? super OTP7, ? extends R> gFn,
                           Fn1<? super OTP8, ? extends R> hFn) {
            return bFn.apply(this);
        }

        @Override
        public Digits digits() {
            return new Digits(2);
        }

        @Override
        public Power power() {
            return new Power(100);
        }
    }

    public static class OTP3 extends OTP {
        public static OTP3 INSTANCE = new OTP3();

        private OTP3() {}

        @Override
        public <R> R match(Fn1<? super OTP1, ? extends R> aFn,
                           Fn1<? super OTP2, ? extends R> bFn,
                           Fn1<? super OTP3, ? extends R> cFn,
                           Fn1<? super OTP4, ? extends R> dFn,
                           Fn1<? super OTP5, ? extends R> eFn,
                           Fn1<? super OTP6, ? extends R> fFn,
                           Fn1<? super OTP7, ? extends R> gFn,
                           Fn1<? super OTP8, ? extends R> hFn) {
            return cFn.apply(this);
        }

        @Override
        public Digits digits() {
            return new Digits(3);
        }

        @Override
        public Power power() {
            return new Power(1_000);
        }
    }

    public static class OTP4 extends OTP {
        public static OTP4 INSTANCE = new OTP4();

        private OTP4() {}

        @Override
        public <R> R match(Fn1<? super OTP1, ? extends R> aFn,
                           Fn1<? super OTP2, ? extends R> bFn,
                           Fn1<? super OTP3, ? extends R> cFn,
                           Fn1<? super OTP4, ? extends R> dFn,
                           Fn1<? super OTP5, ? extends R> eFn,
                           Fn1<? super OTP6, ? extends R> fFn,
                           Fn1<? super OTP7, ? extends R> gFn,
                           Fn1<? super OTP8, ? extends R> hFn) {
            return dFn.apply(this);
        }

        @Override
        public Digits digits() {
            return new Digits(4);
        }

        @Override
        public Power power() {
            return new Power(10_000);
        }
    }

    public static class OTP5 extends OTP {
        public static OTP5 INSTANCE = new OTP5();

        private OTP5() {}

        @Override
        public <R> R match(Fn1<? super OTP1, ? extends R> aFn,
                           Fn1<? super OTP2, ? extends R> bFn,
                           Fn1<? super OTP3, ? extends R> cFn,
                           Fn1<? super OTP4, ? extends R> dFn,
                           Fn1<? super OTP5, ? extends R> eFn,
                           Fn1<? super OTP6, ? extends R> fFn,
                           Fn1<? super OTP7, ? extends R> gFn,
                           Fn1<? super OTP8, ? extends R> hFn) {
            return eFn.apply(this);
        }

        @Override
        public Digits digits() {
            return new Digits(5);
        }

        @Override
        public Power power() {
            return new Power(100_000);
        }
    }

    public static class OTP6 extends OTP {
        public static OTP6 INSTANCE = new OTP6();

        private OTP6() {}

        @Override
        public <R> R match(Fn1<? super OTP1, ? extends R> aFn,
                           Fn1<? super OTP2, ? extends R> bFn,
                           Fn1<? super OTP3, ? extends R> cFn,
                           Fn1<? super OTP4, ? extends R> dFn,
                           Fn1<? super OTP5, ? extends R> eFn,
                           Fn1<? super OTP6, ? extends R> fFn,
                           Fn1<? super OTP7, ? extends R> gFn,
                           Fn1<? super OTP8, ? extends R> hFn) {
            return fFn.apply(this);
        }

        @Override
        public Digits digits() {
            return new Digits(6);
        }

        @Override
        public Power power() {
            return new Power(1_000_000);
        }
    }

    public static class OTP7 extends OTP {
        public static OTP7 INSTANCE = new OTP7();

        private OTP7() {}

        @Override
        public <R> R match(Fn1<? super OTP1, ? extends R> aFn,
                           Fn1<? super OTP2, ? extends R> bFn,
                           Fn1<? super OTP3, ? extends R> cFn,
                           Fn1<? super OTP4, ? extends R> dFn,
                           Fn1<? super OTP5, ? extends R> eFn,
                           Fn1<? super OTP6, ? extends R> fFn,
                           Fn1<? super OTP7, ? extends R> gFn,
                           Fn1<? super OTP8, ? extends R> hFn) {
            return gFn.apply(this);
        }

        @Override
        public Digits digits() {
            return new Digits(7);
        }

        @Override
        public Power power() {
            return new Power(10_000_000);
        }
    }

    public static class OTP8 extends OTP {
        public static OTP8 INSTANCE = new OTP8();

        private OTP8() {}

        @Override
        public <R> R match(Fn1<? super OTP1, ? extends R> aFn,
                           Fn1<? super OTP2, ? extends R> bFn,
                           Fn1<? super OTP3, ? extends R> cFn,
                           Fn1<? super OTP4, ? extends R> dFn,
                           Fn1<? super OTP5, ? extends R> eFn,
                           Fn1<? super OTP6, ? extends R> fFn,
                           Fn1<? super OTP7, ? extends R> gFn,
                           Fn1<? super OTP8, ? extends R> hFn) {
            return hFn.apply(this);
        }

        @Override
        public Digits digits() {
            return new Digits(8);
        }

        @Override
        public Power power() {
            return new Power(100_000_000);
        }
    }
}
