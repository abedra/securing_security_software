# Applying Software Security to Security Software

## Introduction

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
```

The [lambda](https://github.com/palatable/lambda) library provides a rich set of type-safe, functional patterns that
will allow us to remove assumptions, express our essential algorithm, and move toward a formally verifiable expression
of our solution. While I don't consider this type of work required for software security, I do consider it a highly
recommended practice. Security Software is difficult enough to get right, and everything we can do to make it as correct
and verifiable should be considered.

## Essential Algebra

## Removing Assumptions

## Revisiting our Tests

## Wrap-Up