package org.exoplatform.addons.saml.extensions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;

public class IpMatcherTest {

  @Test
  public void emptyOrNullMatchesNothing() {
    assertTrue(new IpMatcher(null).isEmpty());
    assertTrue(new IpMatcher("  ").isEmpty());
    assertFalse(new IpMatcher("").matches("10.0.0.1"));
  }

  @Test
  public void singleAddress() {
    IpMatcher matcher = new IpMatcher("10.0.0.1");
    assertTrue(matcher.matches("10.0.0.1"));
    assertFalse(matcher.matches("10.0.0.2"));
  }

  @Test
  public void cidrBlock() {
    IpMatcher matcher = new IpMatcher("192.168.4.0/22");
    assertTrue(matcher.matches("192.168.4.0"));
    assertTrue(matcher.matches("192.168.7.255"));
    assertFalse(matcher.matches("192.168.8.0"));
    assertFalse(matcher.matches("192.168.3.255"));
  }

  @Test
  public void range() {
    IpMatcher matcher = new IpMatcher("10.1.1.10-10.1.1.20");
    assertTrue(matcher.matches("10.1.1.10"));
    assertTrue(matcher.matches("10.1.1.20"));
    assertFalse(matcher.matches("10.1.1.9"));
    assertFalse(matcher.matches("10.1.1.21"));
  }

  @Test
  public void severalEntriesWithAnySeparator() {
    IpMatcher matcher = new IpMatcher("10.0.0.1, 172.16.0.0/12;192.168.0.5-192.168.0.6\n8.8.8.8");
    assertTrue(matcher.matches("172.31.255.255"));
    assertTrue(matcher.matches("192.168.0.6"));
    assertTrue(matcher.matches("8.8.8.8"));
    assertFalse(matcher.matches("172.32.0.0"));
  }

  @Test
  public void ipv6() {
    IpMatcher matcher = new IpMatcher("2001:db8::/32, ::1");
    assertTrue(matcher.matches("2001:db8:ffff::1"));
    assertTrue(matcher.matches("0:0:0:0:0:0:0:1"));
    assertFalse(matcher.matches("2001:db9::1"));
    // never matches across families
    assertFalse(new IpMatcher("0.0.0.0/0").matches("2001:db8::1"));
  }

  @Test
  public void ipv4MappedIpv6IsAnIpv4Address() {
    assertTrue(new IpMatcher("10.0.0.0/8").matches("::ffff:10.2.3.4"));
  }

  @Test
  public void invalidEntriesAreIgnoredAndNeverResolved() {
    IpMatcher matcher = new IpMatcher("localhost, example.com, 10.0.0.0/33, 10.0.0.9-10.0.0.1, 300.1.1.1, 10.9.9.9");
    assertFalse(matcher.matches("127.0.0.1"));
    assertTrue(matcher.matches("10.9.9.9"));
    assertFalse(matcher.matches("10.0.0.5"));
  }

  @Test
  public void invalidClientAddressNeverMatches() {
    IpMatcher matcher = new IpMatcher("0.0.0.0/0");
    assertFalse(matcher.matches("not-an-ip"));
    assertFalse(matcher.matches(null));
  }

  /** The recording resolver must really be active, or the tests below would pass without proving anything */
  private static void assertResolverIsRecording() {
    RecordingResolverProvider.LOOKUPS.clear();
    // A name never used before: the JDK caches the failed lookups
    String control = "control-" + System.nanoTime() + ".invalid";
    try {
      InetAddress.getByName(control);
    } catch (UnknownHostException e) {
      // expected
    }
    assertTrue(RecordingResolverProvider.LOOKUPS.contains(control), "the recording resolver is not active");
    RecordingResolverProvider.LOOKUPS.clear();
  }

  @Test
  public void malformedEntriesAndAddressesNeverReachTheResolver() {
    assertResolverIsRecording();
    String[] malformed = { "999.1.1.1", "1.2.3", "1.2.3.4.5", "010.0.0.1", "zz:1", "gg::1", "1:2", "::1::2",
                           "1.2.3.4%x", "[::1]", "example.com", "localhost", "10.0.0.0/33", "300.1.1.1-300.1.1.2" };
    IpMatcher matcher = new IpMatcher(String.join(",", malformed));
    for (String value : malformed) {
      assertFalse(matcher.matches(value), value);
    }
    assertTrue(matcher.isEmpty());
    assertTrue(RecordingResolverProvider.LOOKUPS.isEmpty(),
               "no string may be sent to the resolver: " + RecordingResolverProvider.LOOKUPS);
  }

  @Test
  public void validLiteralsDoNotReachTheResolverEither() {
    assertResolverIsRecording();
    IpMatcher matcher = new IpMatcher("10.1.2.3, 2001:db8::/32, ::ffff:10.9.9.9");
    assertTrue(matcher.matches("10.1.2.3"));
    assertTrue(matcher.matches("2001:db8::1"));
    assertTrue(matcher.matches("10.9.9.9"));
    assertTrue(RecordingResolverProvider.LOOKUPS.isEmpty());
  }

  @Test
  public void literalSyntax() {
    assertTrue(IpMatcher.isLiteral("0.0.0.0"));
    assertTrue(IpMatcher.isLiteral("255.255.255.255"));
    assertTrue(IpMatcher.isLiteral("::"));
    assertTrue(IpMatcher.isLiteral("fe80::1"));
    assertFalse(IpMatcher.isLiteral("256.0.0.1"));
    assertFalse(IpMatcher.isLiteral("fe80::1%eth0"));
    assertFalse(IpMatcher.isLiteral(""));
    assertFalse(IpMatcher.isLiteral(null));
  }

  @Test
  public void spacesAroundTheOperatorsAreAccepted() {
    IpMatcher range = new IpMatcher("172.16.5.1 - 172.16.5.50");
    assertTrue(range.matches("172.16.5.20"));
    assertFalse(range.matches("172.16.5.51"));
    assertEquals(1, range.getEntries().size());
    IpMatcher cidr = new IpMatcher("10.0.0.0 / 8 , 192.168.0.1 -192.168.0.3");
    assertTrue(cidr.matches("10.200.1.1"));
    assertTrue(cidr.matches("192.168.0.2"));
    assertEquals(2, cidr.getEntries().size());
  }

  @Test
  public void ipv4MappedCidrCountsTheLeading96Bits() {
    IpMatcher matcher = new IpMatcher("::ffff:10.0.0.0/104");
    assertTrue(matcher.matches("10.9.9.9"));
    assertTrue(matcher.matches("::ffff:10.9.9.9"));
    assertFalse(matcher.matches("11.0.0.1"));
    assertTrue(new IpMatcher("::ffff:10.0.0.0/64").isEmpty());
  }

  @Test
  public void clientAddressesWithAPortOrBracketsAreNormalized() {
    IpMatcher matcher = new IpMatcher("10.0.0.0/8, 2001:db8::/32");
    assertTrue(matcher.matches("10.1.2.3:5555"));
    assertTrue(matcher.matches("[2001:db8::1]:443"));
    assertTrue(matcher.matches("[2001:db8::1]"));
    assertTrue(matcher.matches("fe80::1%eth0") == false);
    assertTrue(IpMatcher.isClientAddress("10.1.2.3:5555"));
    assertTrue(IpMatcher.isClientAddress("fe80::1%eth0"));
    assertFalse(IpMatcher.isClientAddress("10.1.2.3:55:55"));
    assertFalse(IpMatcher.isClientAddress("unknown"));
    assertFalse(IpMatcher.isClientAddress(null));
  }

}
