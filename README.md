# Applying Software Security to Security Software

## Introduction

When it comes to software security, the devil is in the details. When it comes to security software, those details are
even more important. Just recently
a [significant bug](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)
was found in sudo, demonstrating that even the most highly scrutinized software can still contain mistakes. Alexis
King [beautifully captures](https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/) a method that would
have made this bug impossible. Arguably, security software is one of the easier places to justify spending more time on
software security. To separate the ideas I'm going to steal a quote from [Gary McGraw](https://twitter.com/cigitalgem)

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Software security is about integrating security practices into the way you build software, not integrating security features into your code</p>&mdash; Gary McGraw (@cigitalgem) <a href="https://twitter.com/cigitalgem/status/641345011926237185?ref_src=twsrc%5Etfw">September 8, 2015</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

In light of that, let's do some software security in our security software. For this post, we will focus specifically on
the [Totp](https://github.com/Jemurai/how_it_works/blob/master/totp/src/main/java/com/jemurai/howitworks/totp/Totp.java)
class from a [blog post](https://jemurai.com/2018/10/11/how-it-works-totp-based-mfa/) I wrote a few years back while
working at [Jemurai](https://jemurai.com/). [Matt Konda](https://twitter.com/mkonda) was kind enough to let me revisit
the code in this implementation and give it a proper overhaul. I recommend reading the original post for context and
clarity on where we're starting from, but a good understanding of [RFC 6238](https://tools.ietf.org/html/rfc6238) is
enough to get the point.

You can find the complete example for this post
at [https://github.com/abedra/securing_security_software](https://github.com/abedra/securing_security_software)

## Getting Familiar With Dependencies

The very first thing to do is check up on our dependencies to make sure there aren't any issues. To do this we will
add [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) to our project:

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

Keeping up with dependencies should be a first class concept in your SDLC. In reality, you should update your
dependencies as often as possible. If you only wait for security issues to update dependencies, you could be left with
expensive upgrade paths that touch code that has long since fallen out of context with your team. To do this we can add
the [Versions Maven Plugin](https://www.mojohaus.org/versions-maven-plugin/) to our project

```xml

<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>versions-maven-plugin</artifactId>
    <version>2.8.1</version>
</plugin>
```

If we run our new target we can see that we may have some things to address:

```shell
mvn versions:display-dependency-updates
```

```
[INFO] The following dependencies in Dependencies have newer versions:
[INFO]   commons-codec:commons-codec ............................. 1.11 -> 1.15
[INFO]   org.slf4j:slf4j-api ........................... 1.7.25 -> 2.0.0-alpha1
[INFO]   org.slf4j:slf4j-simple ........................ 1.7.25 -> 2.0.0-alpha1
```

While a major version upgrade is out of scope for this post, ideally we would address all of these. The good news is
that the `slf4j` will be completely unused by the time we are done with this exercise and can simply be deleted from our
project. A quick bump from `1.11` to `1.15` on `commons-codec` will be a quick win and we should proceed with that right
away.

```diff
<dependency>
    <groupId>commons-codec</groupId>
    <artifactId>commons-codec</artifactId>
-    <version>1.11</version>
+    <version>1.15</version>
</dependency>
```

Along with keeping up to date I highly recommend adding
the [Maven Enforcer Plugin](https://maven.apache.org/enforcer/maven-enforcer-plugin/) to ensure multiple versions of the
same dependency brought in via dependency resolution do not result in loading outdated, and possibly vulnerable
dependencies.

These types of tools are readily available in most programming languages and I encourage you to add this practice to all
of your projects.

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

Time for a mea culpa on my part. This code completely omitted tests and there's no excuse for that. For something as
important as this it's particularly offensive to not have some kind of verification that the algorithm was implemented
correctly. Why are we discussing tests in a post about Software Security? Writing tests are 100% a part of Software
Security, full stop. Let's revisit the [definition](https://www.techopedia.com/definition/24866/software-security) of
Software Security

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

## Mapping the Process

Because this post is already fairly heavy, I'll save the detailed mapping process for another time. I do think it's
worth mentioning that part of Software Security is grounding your work and making sure you're applying methods that map
to measurable outcomes. Some may disagree on this, but I find this to be useful from both a completeness of practice
perspective as well as a security program management perspective. Doing this produces artifacts that make things like
GRC, compliance, and program maturity measurement more successful and less labor intensive. You may already have
processes around this, but I
find [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
and [BSIMM](https://www.bsimm.com/) very useful guides that apply different but equally useful lenses to the application
and maturity of Software Security.

## Finding the Essential Algebra

Part of applying software security is arriving at a model that allows the full expression of the domain, including
invariants, and nothing more. This is much more difficult than it sounds. It takes thought, several rounds of
refactoring, and good old fashioned discipline. Before we crack into our code it is important to expose a better model
that we can refactor into. Thankfully, this problem lends itself well to very concrete algebra that can be expressed
cleanly and will leave users of this code with an interface that demands domain correct inputs and will fail to compile
otherwise. This creates a rock solid foundation for our refactoring, and will serve as a useful mental exercise ahead of
digging into the previous code.

In [RFC 6238](https://tools.ietf.org/html/rfc6238), there are three concepts that represent essential components of TOTP
and are completely deterministic:

* Time Step - The number of seconds in the TOTP period. 30 seconds is the default, but 60 and 90 are also acceptable
* OTP Length - The number of digits in the final TOTP result. Can be 1 to 8. Also associates an exponent applied to the
  calculation
* HMac Algorithm - The version of the HMac algorithm used in the calculation. Can be SHA1, SHA256, or SHA512

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

It's important to remember that the idea of type-safe, functional programming is a tool used to achieve an outcome. This
is not at all the only way to approach software security so please don't mix the introduction of this idea with the
ability to practice software security. In this particular case, I believe it is a useful tool for demonstrating a point
and find the result incredibly easy to reason about.

Let's start with the time step concept. It allows three options, `30`, `60`, and `90` seconds. This is a great place to
introduce a [CoProduct](https://en.wikipedia.org/wiki/Coproduct). This concept is not built into Java, so we will use
the [lambda supplied implementation](https://github.com/palatable/lambda#coproducts) to give us a hand. Unfortunately,
the end result is very verbose. It is this way partly because of the Java language, and partly because there are some
added ergonomics and performance additions that make things better for consumers. In a language with readily available
CoProducts, this might look something like:

```haskell
data TimeStep = TimeStep30 | TimeStep60 | TimeStep90 deriving (Show)
```

The resulting Java code is long enough that I prefer linking instead of a direct copy and paste. The result can be
found [here](https://github.com/abedra/securing_security_software/blob/master/src/main/java/com/aaronbedra/swsec/TimeStep.java)
. While there's a lot of ceremony under the hood, the real interface is provided by the `timeStep30()`, `timeStep60()`,
and `timeStep90()` methods. Notice that each of the `TimeStep` inner classes carries a value, which ensures that the
respective class can only contain the correct number of seconds. Ultimately, requiring the `TimeStep` type in the
implementation of our algorithm ensures at the type level that this concept in our algorithm will be correct. Any
substitution will be considered a type error and your program will fail to compile. This ensures the time step cannot be
abused or misused in our implementation.

Next, let's take a look at OTP length. This controls the resulting length of the TOTP code, and should carry with it the
appropriate exponent to use during the TOTP calculation. Again, we can reach for a CoProduct, but this time it's a bit
longer given our options are one to eight. You can find the full
implementation [here](https://github.com/abedra/securing_security_software/blob/master/src/main/java/com/aaronbedra/swsec/OTP.java)
. Like the time step implementation, there's an ergonomic interface on top of the required ceremony. Each instance
of `OTP` has a resulting `Digits` and `Power` that are used to represent the length and exponent, ensuring these values
cannot be used incorrectly.

The HMac type was intentionally saved for last, because it will carry some additional implementation. Along with the
ability to correctly specify the HMac algorithm, we also want this type to be able to furnish an HMac result. Given a
TOTP Seed, a desired HMac algorithm, and a Counter, we should be able to furnish the result of the HMac operation with
full assurance that the correct usage was respected and cannot be abused or misused. The full implementation can be
found [here](https://github.com/abedra/securing_security_software/blob/master/src/main/java/com/aaronbedra/swsec/HMac.java)
. Like the other types we will start again with a CoProduct, differentiating on the HMac algorithm. Along with the
ergonomics offered by the other types you will notice a few things that are worth digging into. The `hexToBytes` method
has been pulled into this class and renamed to `generateKey`. Ultimately this method provides our arrow from our TOTP
Seed to the resulting HMac key used in the operation. You will also notice it replaces the Java native return type
of `byte[]` with the `HmacKey` record type. I find the expression of tiny, or marker, types to be a very useful exercise
when writing code. It helps keep track mentally of all the inputs and outputs, and provides a simple layer of compile
time protection against supplying the wrong input to the wrong place. This pattern will continue throughout the
refactoring. The most substantial difference is the implementation of `hash`. This is the same `hash` method from the
initial implementation refactored to adequately express the underlying complexity. This one is worth a before and after
so let's take a look.

```java
public final class Totp {
    private static byte[] hash(final byte[] key, final byte[] message) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA1");
            SecretKeySpec keySpec = new SecretKeySpec(key, "RAW");
            hmac.init(keySpec);
            return hmac.doFinal(message);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }
}
```

My oh my, where do we begin. On the plus side, if you don't look back at code you wrote previously with severe disdain,
it's a sign you haven't grown. At least I've got that going for me. Let's itemize the things that need to change here:

* Explicit types for each input and output
* Logging has absolutely no place here and needs to be removed
* Returning `null` carries no information about the failure and forces the consumer to handle it
* We need a better way to propagate the failure without throwing an exception
* JCA operations perform side effects
* There's no ability to ask for alternate HMac algorithms

To do this we will want a method that returns an `IO` wrapping some concept of success and failure. We can use
an `Either` for this. A bit of refactoring and we can produce the following:

```java
public abstract class HMac implements CoProduct3<HMac.HMacSHA1, HMac.HMacSHA256, HMac.HMacSHA512, HMac> {
    public IO<Either<Failure, HmacResult>> hash(Seed seed, Counter counter) {
        HmacKey key = generateKey(seed);

        return getInstance()
                .flatMap(hmac -> io(() -> new SecretKeySpec(key.value(), "RAW"))
                        .flatMap(secretKeySpec -> io(() -> hmac.init(secretKeySpec)))
                        .flatMap(constantly(io(() -> Either.<Failure, HmacResult>right(new HmacResult(hmac.doFinal(counter.value())))))))
                .catchError(throwable -> io(left(new Failure(throwable))));
    }
}
```

Here we capture the side effects, but consider any exception thrown inside calculating the HMac value a failure. There
are two new record types, `Failure` and `HmacResult` respectively. This allows the consumer to exhaustively handle the
outcome of calling this method, and use the success or failure information in total in whatever way is appropriate. This
gets the logging out of the picture and lets us call that code in a more appropriate place. In terms of side effects, we
have four separate operations that perform them. First is the call to `Mac.getInstance`, which we have made an
implementation detail of each member of our CoProduct. The second is creating our instance of `SecretKeySpec`, the third
calling `init`, and finally the invocation of `doFinal`. Depending on how you have
configured [JCA](https://docs.oracle.com/en/java/javase/15/security/java-cryptography-architecture-jca-reference-guide.html#GUID-2BCFDD85-D533-4E6C-8CE9-29990DEB0190)
those effects can vary. This method also introduces the `Seed` and `Counter` record types which have not yet been
defined. We are left with a resulting representation of HMac that covers our domain and prevents misuse and abuse of the
input space. Additionally, this will allow us to remove some older and now duplicate code from the `Totp` class.

Since we've introduced the concept of `Seed` and `Counter`, let's define them, starting with `Seed`. Let's spend a
little time identifying its implicit assumptions. This effort is a critical part of understanding how and why software
can fail, and will allow us to model our solution more completely. This step is a very effective tool in the Software
Security tool belt and goes a long way in producing solutions that operate correctly under uncertainty. Let's start with
the `generateSeed` method.

```java
 public final class Totp {
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
public record Seed(String value){
public static ReaderT<SecureRandom, IO<?>,Seed>generateSeed(int length){
        return readerT(secureRandom->io(()->{
        byte[]randomBytes=new byte[length];
        secureRandom.nextBytes(randomBytes);
        return new Seed(encodeHexString(randomBytes));
        }));
        }
        }
```

It is important to note that we have now taken the first step toward parameterizing both the mechanism that produces
bytes, and the effect that byte production runs under. This is thanks to `ReaderT`. This post is already long enough
that a detailed explanation of `ReaderT` is not in the cards. There is, however, a
good [blog post](https://www.fpcomplete.com/blog/2017/06/readert-design-pattern/) on the pattern that should help build
a foundation. The syntax is a bit different in Java, but the idea is the same. There's a bit to unpack here, so let's go
through it in more detail. The `generateSeed` method no longer directly returns a `Seed`, but rather a function that,
when provided an instance of `SecureRandom`, will produce another function that, when run, will perform the side effect
and produce a seed. This gets us closer to our statement above and correctly captures the details around how random
bytes are produced. Notice that we have also moved our method into a `Seed` record type since it is effectively a static
constructor, and, the only interface into `Seed` that we care about.

Next, let's introduce `Counter`. Just like `Seed`, we will extract our code into a record. We will start with the
original `counterToBytes`:

```java
public final class Totp {
    private static byte[] counterToBytes(final long time) {
        long counter = time / PERIOD;
        byte[] buffer = new byte[Long.SIZE / Byte.SIZE];
        for (int i = 7; i >= 0; i--) {
            buffer[i] = (byte) (counter & 0xff);
            counter = counter >> 8;
        }
        return buffer;
    }
}
```

Again, this method contains assumptions we would like to eliminate. The most egregious being the idea that `PERIOD` is a
constant and cannot be changed without modifying the implementation. This was originally done to make the example a lean
as possible, but in reality goes against expectations. The good news is, that we have already defined `TimeStep`, and
that's exactly what we are going to use in its place. We end up with the following:

```java
public record Counter(byte[]value){
public static Counter counter(TimeStamp timeStamp,TimeStep timeStep){
        long counter=timeStamp.value()/timeStep.value();
        byte[]buffer=new byte[Long.SIZE/Byte.SIZE];
        for(int i=7;i>=0;i--){
        buffer[i]=(byte)(counter&0xff);
        counter=counter>>8;
        }
        return new Counter(buffer);
        }
        }
```

The implementation hasn't changed much. We made the time step an explicit requirement, and introduce a tiny type for the
current time, `TimeStamp`. Other than returning an instance of `Counter` the calculation of the `Counter` is the same.

While we're here, let's follow up with our definition of `TimeStamp`. You might guess it's just an empty record
definition that holds a `long`, and you would be correct. Because we will at some point need to get the current time
from the system to do our calculation, we will have one more side effect. To capture this, we will add a static
constructor `now` to our record to complete it:

```java
public record TimeStamp(long value){
public static IO<TimeStamp> now(){
        return io(()->new TimeStamp(System.currentTimeMillis()/1000));
        }
        }
```

Here we remove the underlying assumption around what really happens when we reach for the system clock. This also lets
us compose getting the current time with any other `IO` operations. This will come in handy in a bit.

At this point we can now set our sights on the `Totp` class. We have all the foundation we need to do a successful
refactoring. We can start by deleting the majority of this class, which is always satisfying. This includes all of
the `static final` variables created at the top of the class, the `generateSeed()` method, `hexToBytes()`
, `counterToBytes()`, and `hash`. Let's also turn our `Totp` class into a record holding a `String` value. All we really
have left to set our sights on is `generateInstance()`. There's a lot going on here, arguably more than there needs to
be. Let's start by splitting some of this up:

```java
public record Totp(String value){
private static int calculate(HmacResult hmacResult){
        byte[]result=hmacResult.value();
        int offset=result[result.length-1]&0xf;
        return((result[offset]&0x7f)<<24)|
        ((result[offset+1]&0xff)<<16)|
        ((result[offset+2]&0xff)<<8)|
        ((result[offset+3]&0xff));
        }

private static Totp totp(int totpBinary,OTP otp){
        String code=Integer.toString(totpBinary%otp.power().value());
        int length=otp.digits().value()-code.length();

        return length>0
        ?new Totp("0".repeat(length)+code)
        :new Totp(code);
        }
        }
```

This separates out the calculation of the TOTP binary value as well as the construction of the final number. It also
ditches the `while` loop that was padding the value based on the `OTP` power. What's left, you might ask. Well, not
much. The only thing left is to coordinate it all. That we can save for our `generateInstance()` method:

```java
public record Totp(String value){
public static IO<Either<Failure, Totp>>generateInstance(OTP otp,HMac hMac,Seed seed,Counter counter){
        return hMac.hash(seed,counter)
        .fmap(eitherFailureHmacResult->eitherFailureHmacResult
        .biMapR(hmacResult->totp(calculate(hmacResult),otp)));
        }
        }
```

Yet again, another radical departure. To callers, our method went from returning `String`,
to `IO<Either<HmacFailure, TOTP>>`, which forces the caller to consider and appropriately handle failure. The only
additional code here is to provide the arrow from `IO<Either<HmacFailure, HmacResult>>`
to `IO<Either<HmacFailure, TOTP>>`, which we solve by calling `fmap` on the result of our `hash` method, then
calling `biMapR`, which operates on the right value of our either and transforms it into its final form. We can
use `biMapR` here because we are currently ok with preserving the failure type and only wish to transform the success
of `hash`. The full implementation of our `Totp` class can be
found [here](https://github.com/abedra/securing_security_software/blob/master/src/main/java/com/aaronbedra/swsec/Totp.java)
.

Next, we need to address the changes to our test. Now is a good time to
introduce [Shōki](https://github.com/palatable/shoki), a purely functional, persistent data structures library. This is
going to provide some better ergonomics for our test updates.

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
    public void googleAuthenticator() {
        Seed seed = new Seed("3132333435363738393031323334353637383930");
        StrictStack<Counter> counters = strictStack(
                counter(new TimeStamp(59L), timeStep30()),
                counter(new TimeStamp(1111111109L), timeStep30()),
                counter(new TimeStamp(1111111111L), timeStep30()),
                counter(new TimeStamp(1234567890L), timeStep30()),
                counter(new TimeStamp(2000000000L), timeStep30()),
                counter(new TimeStamp(20000000000L), timeStep30()));

        StrictQueue<Either<Failure, Totp>> expected = strictQueue(
                right(new Totp("287082")),
                right(new Totp("081804")),
                right(new Totp("050471")),
                right(new Totp("005924")),
                right(new Totp("279037")),
                right(new Totp("353130")));

        StrictQueue<Either<Failure, Totp>> actual = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(otp6(), hMacSHA1(), seed, value).unsafePerformIO()),
                strictQueue(),
                counters);

        assertEquals(expected, actual);
    }
}
```

Along with updating our test to respect the new interface, we got rid of the older style `for` loop and landed with a
single assertion. Because our objects are all immutable, we should be able to directly compare expected and actual, and
get a proper equality check. The `foldLeft` operation takes the `Counter` values and accumulates the result of
generating a `TOTP` value for each into a `StrictQueue`, so we can easily compare. This fixes the compiler errors
associated with our refactoring, and makes the test a little cleaner, but what about accounting for the newly added
range of inputs? Let's create a test to cover the entire spectrum provided by the sample implementation
in [RFC 6238](https://tools.ietf.org/html/rfc6238).

```java
public class TotpTest {
    @Test
    public void rfc6238() {
        Seed seed = new Seed("3132333435363738393031323334353637383930");
        Seed seed32 = new Seed("3132333435363738393031323334353637383930313233343536373839303132");
        Seed seed64 = new Seed("31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334");

        StrictStack<Counter> counters = strictStack(
                counter(new TimeStamp(59L), timeStep30()),
                counter(new TimeStamp(1111111109L), timeStep30()),
                counter(new TimeStamp(1111111111L), timeStep30()),
                counter(new TimeStamp(1234567890L), timeStep30()),
                counter(new TimeStamp(2000000000L), timeStep30()),
                counter(new TimeStamp(20000000000L), timeStep30()));


        StrictQueue<Either<Failure, Totp>> expectedSha1 = strictQueue(
                right(new Totp("94287082")),
                right(new Totp("07081804")),
                right(new Totp("14050471")),
                right(new Totp("89005924")),
                right(new Totp("69279037")),
                right(new Totp("65353130")));

        StrictQueue<Either<Failure, Totp>> expectedSha256 = strictQueue(
                right(new Totp("46119246")),
                right(new Totp("68084774")),
                right(new Totp("67062674")),
                right(new Totp("91819424")),
                right(new Totp("90698825")),
                right(new Totp("77737706")));

        StrictQueue<Either<Failure, Totp>> expectedSha512 = strictQueue(
                right(new Totp("90693936")),
                right(new Totp("25091201")),
                right(new Totp("99943326")),
                right(new Totp("93441116")),
                right(new Totp("38618901")),
                right(new Totp("47863826")));

        StrictQueue<Either<Failure, Totp>> actualSha1 = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(otp8(), hMacSHA1(), seed, value).unsafePerformIO()),
                strictQueue(),
                counters);

        StrictQueue<Either<Failure, Totp>> actualSha256 = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(otp8(), hMacSHA256(), seed32, value).unsafePerformIO()),
                strictQueue(),
                counters);

        StrictQueue<Either<Failure, Totp>> actualSha512 = foldLeft(
                (acc, value) -> acc.snoc(generateInstance(otp8(), hMacSHA512(), seed64, value).unsafePerformIO()),
                strictQueue(),
                counters);

        assertEquals(expectedSha1, actualSha1);
        assertEquals(expectedSha256, actualSha256);
        assertEquals(expectedSha512, actualSha512);
    }
}
```

This test represents full parity with the RFC implementation, which should provide additional confidence in our
refactoring.

The last thing we need to do is update our `Main` class and get our example working again.

```java
public class Main {
    public static void main(String[] args) {
        generateSeed(64)
                .<IO<Seed>>runReaderT(new SecureRandom())
                .zip(now().fmap(tupler()))
                .flatMap(into((timeStamp, seed) -> generateInstance(otp6(), hMacSHA1(), seed, counter(timeStamp, timeStep30()))))
                .flatMap(failureOrTotp -> failureOrTotp.match(
                        hmacFailure -> io(() -> System.out.println(hmacFailure.value().getMessage())),
                        totp -> io(() -> System.out.println(totp))))
                .unsafePerformIO();
    }
}
```

This is where composition pays off very nicely. To better explain what's going on under the hood here we can break down
all of the chained calls into their specific types:

```java
public class Main {
    public static void main(String[] args) {
        ReaderT<SecureRandom, IO<?>, Seed> seedReaderT = generateSeed(64);
        IO<Seed> seedIO = seedReaderT.runReaderT(new SecureRandom());
        IO<Tuple2<TimeStamp, Seed>> timeStampAndSeed = seedIO.zip(now().fmap(tupler()));
        IO<Either<Failure, Totp>> failureOrInstance = timeStampAndSeed
                .flatMap(into((timeStamp, seed) -> generateInstance(otp6(), hMacSHA1(), seed, counter(timeStamp, timeStep30()))));
        IO<Unit> unitIO = failureOrInstance
                .flatMap(failureOrTotp -> failureOrTotp.match(
                        hmacFailure -> io(() -> System.out.println(hmacFailure.value().getMessage())),
                        totp -> io(() -> System.out.println(totp))));
        Unit __ = unitIO.unsafePerformIO();
    }
}
```

Generating our seed returns a `ReaderT`. We run that `ReaderT` by supplying it an instance of `SecureRandom`. This
allows the caller to control how randomness will behave. Our system should not dictate how random works, just that it is
able to get random bytes. Since the `ReaderT` runs under `IO`, We will get an `IO` that when executed, returns our seed.
Since `IO` composes very nicely in lambda, we don't need to run it just yet. We have plenty of additional side effects
left in our method, and we will use `flatMap` to stitch them together. I could write an entire post on the ways to do
that with lambda, but for now we can interpret this as each `IO` will execute strictly before the `IO` executed in
the `flatMap` that follows it. The next thing we will do is get the current time. Our `now()` method returns an `IO`
that, when executed, returns our `TimeStamp`. These operations are truly independent of each other, but are both
required inputs for generating an instance of `Totp`. We use lambda's `zip` method and create a tuple that provides both
for the next step. We can now call `generateInstance()` with enough information to get a value. Notice that we are
using `OTP6`, `HmacSHA1`, and `TimeStep30`. Not only is this now safe by construction, it's very obvious exactly how the
TOTP value will be generated. Since this call returns an `IO` that introduces failure, we will need to handle both the
success and failure cases. We do this with `match`, and print the resulting value in both cases. At this point, we have
constructed a single `IO` that fuses all of our side effects together. The last thing we need to do is
call `unsafePerformIO()` to actually run the `IO` and produce our result. The resulting `UNIT` is simply for explanatory
reasons so we can demonstrate that we are in fact returned with a real value after executing our code. A few keystrokes
to inline all these variables will get us back to the originally presented version. Running it will produce something
similar to the following:

```
Totp[value=441923]
```

That's it, we made it! It was quite a journey, but hopefully you have a new found appreciation of the details, and how
they can apply to Software Security.

## Wrap-Up

You may still be waiting for the rest of the security content. The answer is that we were applying it this whole time.
If we look back at the definition of software security, the work done here supports almost all of these goals. Bonus
points for TOTP being in the authentication domain. Correctness, testing, and protection from supplying inputs that
cause the algorithm to function incorrectly. At times you may have wondered how far to actually go with these concepts.
Providing type level evidence of correctness is not always easy or straight forward, and working towards a more
verifiable model always carries a higher cost. Some people subscribe to this type of programming as a way of life, some
as a tool to assist in solving complex problems, and some not at all. Not matter your thoughts on this specific
approach, practicing Software Security should be on your requirements for delivery of software. When applied properly,
the impact of better Software Security is software that operates correctly under failure, is better tested, and
typically easier to understand.

After completing this refactoring, I decided to turn the result into a full library. You can find the project
at [https://github.com/abedra/chronometrophobia](https://github.com/abedra/chronometrophobia)

If you're looking to learn more about software security, I highly recommend checking
out [Secure Code Warrior](https://www.securecodewarrior.com/). They have an excellent training platform, and
their [Sensei](https://www.securecodewarrior.com/sensei) IDE plugin is great at helping you and your team apply more
secure software development habits in real time.
