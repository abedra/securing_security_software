# Applying Software Security to Security Software

## Introduction

TODO: Write

## Getting Familiar With Dependencies

For this post, we will focus specifically on
the [Totp](https://github.com/Jemurai/how_it_works/blob/master/totp/src/main/java/com/jemurai/howitworks/totp/Totp.java)
class from the original post. The very first thing to do is check up on our dependencies to make sure there aren't any
issues. To do this we will add [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) to our project:

```xml

<build>
    <plugins>
        <plugin>
            <groupId>org.owasp</groupId>
            <artifactId>dependency-check-maven</artifactId>
            <version>6.0.5</version>
            <configuration>
                <failBuildOnCVSS>1</failBuildOnCVSS>
            </configuration>
            <executions>
                <execution>
                    <goals>
                        <goal>check</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

I prefer to set the `failBuildOnCVSS` option to `1`. This forces evaluation and explicit action on everything found. It
is completely acceptable to suppress a vulnerability if it does not impact your system, and using the value of `1` here
will force you to upgrade or suppress. When suppression is chosen, be sure to add a detailed commit message that
explains your choice and why it should be suppressed rather than updated. If you couple this with peer review, you can
get into a workflow where all suppressions have approval from another person and there's ample opportunity for
discussion. Adding peer approved suppression is just as important as adding the dependency analysis tooling and should
be considered an absolute requirement.

The first run of Dependency Check can take a while because of the CVE database updates. Now is a good time to get the
first run out of the way so subsequent runs and execute faster.

```shell
mvn dependency-check:aggregate
```

## An Updated Language Version

The original project was built using Java 8. Java 8 is now well past its end of life and upgrading should be seriously
considered. While I typically recommend snapping to the latest LTS release, we are going to Java 15 in this example to
get some of the latest features that will make our updates more concise. It would be completely reasonable to bump to
Java 11 here as it is the current LTS version, but the introduction
of [Records](https://blogs.oracle.com/javamagazine/records-come-to-java) is a great way to quickly introduce new
immutable types without a ton of boilerplate.

```xml

<properties>
    <maven.compiler.source>15</maven.compiler.source>
    <maven.compiler.target>15</maven.compiler.target>
</properties>
```

Unfortunately, upgrading is not as simple as changing the version. The `javax.xml.bind.DatatypeConverter` class was
deprecated in Java 9 and removed in Java 11. The good news is that our project already has the `commons-codec`
dependency, and we are a method call replacement away from compiling properly again:

```diff
    static String generateSeed() {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[SEED_LENGTH_IN_BYTES];
        random.nextBytes(randomBytes);

-       return printHexBinary(randomBytes);
+       return encodeHexString(randomBytes);
    }
```

## Adding Tests

Time for a pretty major mea culpa on my part. This code completely omitted tests and there's no excuse for that. For
something as important as this it's especially offensive to not have some kind of verification that the algorithm was
implemented correctly. Why are we discussing tests in a post about Software Security? Writing tests are 100% a part of
Software Security, full stop. Let's revisit
the [definition](https://www.techopedia.com/definition/24866/software-security) of Software Security

> Software security is an idea implemented to protect software against malicious attack and other hacker risks so that the software continues to function correctly under such potential risks. Security is necessary to provide integrity, authentication and availability.

It turns out functioning correctly is also a part of Software Security. Next time you think about not writing tests,
consider them a fundamental aspect to the overall security of your software.

As it sits, randomness is built into our example without sufficient control of the state of the inputs. This makes it
difficult to test and should be considered a design issue. Before we go refactoring our code too much we do need some
kind of sanity check to make sure we don't accidentally break our implementation.
Thankfully, [RFC 6238](https://tools.ietf.org/html/rfc6238) has input and output examples that we can use to put
together a basic end-to-end test. If we break anything in the essential algorithm this test will tell us.

```java
public class TotpTest {
    @Test
    public void endToEnd() {
        String seed = "3132333435363738393031323334353637383930";
        long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] expectedOutputs = {"287082", "081804", "050471", "005924", "279037", "353130"};
        for (int i = 0; i < times.length; i++) {
            assertEquals(expectedOutputs[i], generateInstance(seed, counterToBytes(times[i])));
        }
    }
}
```

In order to make this test work, we will need to loosen the modifier for `counterToBytes` and make it at the very least
package private. I'm generally a fan of not relying on package location to determine what a class should expose, and
this method should be generally considered part of the interface offered to support things like drift.

```diff
-   private static byte[] counterToBytes(final long time) {
+   public static byte[] counterToBytes(final long time) {
        long counter = time / PERIOD;
        byte[] buffer = new byte[Long.SIZE / Byte.SIZE];
        for (int i = 7; i >= 0; i--) {
            buffer[i] = (byte) (counter & 0xff);
            counter = counter >> 8;
        }
        return buffer;
    }
```

The end-to-end test should now pass, and we have a viable baseline to use as we proceed.

## Replacing Native Language Types

Before we into the heavy lifting, I find it useful to completely break away from native language types. This practice
can be polarizing, but I find it essential to the proper expression of the domain. This expression will become more
obvious as we start our refactoring and introduce more complex types. This is where having Java's `Record` support comes
in handy. This practice is borrowed from
Haskell's [newtype](https://kowainik.github.io/posts/haskell-mini-patterns#newtype) pattern. While this example will
mostly wrap language types in value types, this concept can and should be taken much further to model domain invariants.
Alexis King does a [fantastic job](https://lexi-lambda.github.io/blog/2020/11/01/names-are-not-type-safety/) taking
this [further](https://lexi-lambda.github.io/blog/2020/08/13/types-as-axioms-or-playing-god-with-static-types/).

Let's start by defining types for our `Totp` class. Because the record syntax allows us to define value types in a very
small space we can add them all to the same file. Let's start with the two essential output types of the `Totp` class.

```java
public final class Types {
    public static record Seed(String value) {
    }

    public static record TOTP(String value) {
    }
}
```

We will add to this as we go, but these are the two types used by consumers of our library. Both of these have moved
from `String` to a value type holding a string. While that might seem trivial, think of what each represents. The
underlying value of a `Seed` is a much more sensitive value than `TOTP` and should be treated with more care. Going
forward we now have an easy way to understand that a `Seed` is a `Seed` and can apply the appropriate restrictions.
Let's take a look at our `Main` class to see how the program changes:

```diff
public class Main {
    public static void main(String[] args) {
-        String seed = Totp.generateSeed();
+        Seed seed = Totp.generateSeed();
-        String totp = generateInstance(seed);
+        TOTP totp = generateInstance(seed);
        System.out.println(totp);
    }
}
```

Consumers are minimally impacted but now have a much richer set of information to work with. It is now considered an
error by the compiler to pass a `String` to `generateInstance`. We are starting to enforce requirements on the use of
our library that uses domain concepts to express input and output details. Updates to the `Totp` class are skipped here
for brevity, and because this class will change significantly before our end state.

## Introducing lambda

Before we continue, we are going to add another library to assist us:

```xml

<dependencies>
    <dependency>
        <groupId>com.jnape.palatable</groupId>
        <artifactId>lambda</artifactId>
        <version>5.3.0</version>
    </dependency>
    <dependency>
        <groupId>com.jnape.palatable</groupId>
        <artifactId>lambda</artifactId>
        <version>5.3.0</version>
        <type>test-jar</type>
        <scope>test</scope>
    </dependency>
</dependencies>
```

The [lambda](https://github.com/palatable/lambda) library provides a rich set of type-safe, functional patterns that
will allow us to remove assumptions, express our essential algorithm, and move toward a formally verifiable expression
of our solution. While I don't consider this type of work required for software security, I do consider it a highly
recommended practice. Security Software is difficult enough to get right, and everything we can do to make it as correct
and verifiable should be considered.

## Removing Assumptions

Before we get to the essential complexity behind our implementation, let's spend a little time identifying its implicit
assumptions. This effort is a critical part of understanding how and why software can fail, and will allow us to model
our solution more completely. This step is a very effective tool in the Software Security tool belt and goes a long way
in producing solutions that operate correctly under uncertainty. Let's start with the `generateSeed` method.

```java
 public final class Totp {
    // ...
    public static Seed generateSeed() {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[SEED_LENGTH_IN_BYTES];
        random.nextBytes(randomBytes);

        return new Seed(encodeHexString(randomBytes));
    }
}
```

On the surface this method looks fairly straight forward. Its purpose is to produce a hex encoded string of random
bytes. Unfortunately, it's filled with assumptions. Ultimately, we should be able to say

> Given a number and a mechanism to furnish bytes, give me back a hex encoded string of the provided number of random bytes

Sounds simple enough, right? Well, that's where the assumptions kick in. This method assumes that seed generation should
control how byte furnishing is constructed, and the number of bytes that should be generated. This method also doesn't
account for the fact that generating a random number using CSPRNG has a side effect. Since we're striking out on a
number of levels, let's try a more explicit representation:

```java
public final class Totp {
    public static ReaderT<SecureRandom, IO<?>, Seed> generateSeed(int length) {
        return readerT(secureRandom -> io(() -> {
            byte[] randomBytes = new byte[length];
            secureRandom.nextBytes(randomBytes);
            return new Seed(encodeHexString(randomBytes));
        }));
    }

    public static void main(String[] args) {
        ReaderT<SecureRandom, IO<?>, Seed> secureRandomIOSeedReaderT = generateSeed(64);
        IO<Seed> seedIO = secureRandomIOSeedReaderT.runReaderT(new SecureRandom());
        Seed seed = seedIO.unsafePerformIO();
        System.out.println(seed);
    }
}
```

There's a bit to unpack here, so let's go through it in more detail. The `generateSeed` method no longer directly
returns a `Seed`, but rather a function that, when run with an instance of `SecureRandom`, will produce another function
that, when run, will perform the side effect and produce a seed. This gets us closer to our statement above and
correctly captures the details around how random bytes are produced. The `main` above is broken down into each piece for
clarity, but can be rewritten as:

```java
public final class Totp {
    public static void main(String[] args) {
        Seed seed = generateSeed(64)
                .<IO<Seed>>runReaderT(new SecureRandom())
                .unsafePerformIO();
        System.out.println(seed);
    }
}
```

It is important to note that we have now taken the first step toward parameterizing both the mechanism that produces
bytes, and the effect that byte production runs under. This is thanks to `ReaderT`. This post is already long enough
that a detailed explanation of `ReaderT` is not in the cards. There is, however, a
good [blog post](https://www.fpcomplete.com/blog/2017/06/readert-design-pattern/) on the pattern that should help build
a foundation. The syntax is a bit different in Java, but the idea is the same.

We will take parameterization a bit further on this later, but for now there's more work to do around correctly
capturing the assumptions of our algorithm. Let's set our sights on `generateInstance`. To better understand what's
going on here lets delete the convenience methods and focus explicitly on the real implementation:

```java
public final class Totp {
    public static TOTP generateInstance(Seed seed, final byte[] counter) {
        // ...
    }

    public static void main(String[] args) {
        TOTP totp = generateInstance(seed, counterToBytes(System.currentTimeMillis() / 1000));
    }
}
```

We can express this as:

> Given a seed and a counter, give me back a one time password

You may have already identified the call to `System.currentTimeMillis` though and recognized the side effect. To capture
this we should alter our expression to:

> Given a seed and mechanism to furnish a counter, give me back a one time password

This we can accomplish fairly easily. If we isolate the side effect we can in turn have `generateInstance` return a side
effect:

```java
public final class Totp {
    public static IO<TOTP> generateInstance(Seed seed, IO<Counter> mkCounter) {
        return mkCounter.flatMap(counter -> io(() -> {
            byte[] key = hexToBytes(seed.value());
            byte[] result = hash(key, counter.value());

            if (result == null) {
                throw new RuntimeException("Could not produce OTP value");
            }

            int offset = result[result.length - 1] & 0xf;
            int binary = ((result[offset] & 0x7f) << 24) |
                    ((result[offset + 1] & 0xff) << 16) |
                    ((result[offset + 2] & 0xff) << 8) |
                    ((result[offset + 3] & 0xff));

            StringBuilder code = new StringBuilder(Integer.toString(binary % POWER));

            while (code.length() < DIGITS) {
                code.insert(0, "0");
            }

            return new TOTP(code.toString());
        }));
    }
}
```

Now our TOTP instance generation assumes a side effect. Our battle with this method is far from over, but at least it's
no longer lying about what it does. Well, it's at least not lying about the side effect. We will take care of that
exception shortly. Our method now runs the effect that produces our counter value and then computes the TOTP value.

This is a breaking API change, and we will need to update our consumers to account for the changes. Let's start
with `Main`:

```java
public class Main {
    public static void main(String[] args) {
        generateSeed(64)
                .<IO<Seed>>runReaderT(new SecureRandom())
                .flatMap(seed -> generateInstance(seed, io(() -> new Counter(counterToBytes(System.currentTimeMillis() / 1000)))))
                .flatMap(totp -> io(() -> System.out.println(totp)))
                .unsafePerformIO();
    }
}
```

Because we have begun capturing our side effects, we can now run our entire program under a single `IO` operation. We
start by running the `ReaderT` to produce the `IO` that holds our `Seed`, then we `flatMap` into the `IO` that produces
our `TOTP`. Finally, printing to `stdout` is also a side effect, so we can `flatMap` into one final `IO` to produce our
output. None of these `IO` operations are actually run until our call to `unsafePerformIO`. There are multiple options
for running `IO` in lambda, but since we are running each effect strictly after the one that precedes it, options
like `unsafePerformAsyncIO` to perform them in parallel don't apply in our scenario.

Next, we need to address the changes to our test. Now is a good time to
introduce [Shōki](https://github.com/palatable/shoki), a purely functional, persistent data structures library. This is
going to provide some better ergonomics for our test updates. Additionally, Shoki offers an implementation of `Natural`
that will allow us to better express our input requirements.

```xml

<dependency>
    <groupId>com.jnape.palatable</groupId>
    <artifactId>shoki</artifactId>
    <version>1.0-alpha-2</version>
</dependency>

```

With Shoki in hand, let's update our tests:

```java
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
```

Along with updating our test to respect the new interface, we got rid of the older style `for` loop and landed with a
single assertion. Because our objects are all immutable, we should be able to directly compare expected and actual, and
get a proper equality check. The `foldLeft` operation takes the `Counter` values and accumulates the result of
generating a `TOTP` value for each into a `StrictQueue`, so we can easily compare. You might be wondering why we need to
wrap each of our `Counter` values in `IO`, and you would be right to question that. In our test there's no side effect
happening to produce our value. The essential algebra is starting to reveal itself. Before we can get to that we need to
do a little more refactoring, so let's leave the unnecessary `IO` here for now and continue forward.

## Essential Algebra

TODO: Write

## Revisiting our Tests

TODO: Write

## Wrap-Up

TODO: Write
