package org.exoplatform.addons.saml.extensions;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

/**
 * Matches a client IP address against a list of IPv4/IPv6 addresses, CIDR
 * blocks and ranges. Entries are separated by comma, semicolon or whitespace:
 * <ul>
 * <li>{@code 10.1.2.3}: a single address</li>
 * <li>{@code 10.0.0.0/8} or {@code 2001:db8::/32}: a CIDR block</li>
 * <li>{@code 192.168.1.10-192.168.1.50}: an inclusive range</li>
 * </ul>
 * Spaces around the {@code -} and the {@code /} are accepted. Only literal
 * addresses are accepted, host names are never resolved. An invalid entry is
 * ignored and reported at error level: it enforces nothing.
 */
public class IpMatcher {

  private static final Log     LOG              = ExoLogger.getLogger(IpMatcher.class);

  private static final Pattern IPV4_LITERAL     = Pattern.compile("(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}");

  private static final Pattern SEPARATORS       = Pattern.compile("[,;\\s]+");

  private static final Pattern SPACED_OPERATORS = Pattern.compile("\\s*([-/])\\s*");

  private final List<Range>    ranges           = new ArrayList<>();

  private final List<String>   accepted         = new ArrayList<>();

  public IpMatcher(String entries) {
    if (entries == null) {
      return;
    }
    String normalized = SPACED_OPERATORS.matcher(entries.trim()).replaceAll("$1");
    for (String entry : SEPARATORS.split(normalized)) {
      if (!entry.isEmpty()) {
        try {
          ranges.add(parse(entry));
          accepted.add(entry);
        } catch (IllegalArgumentException e) {
          LOG.error("Invalid entry '{}' in the SAML enforced IP list, it enforces nothing: {}", entry, e.getMessage());
        }
      }
    }
  }

  public boolean isEmpty() {
    return ranges.isEmpty();
  }

  /**
   * @return the entries that are in effect, for the logs
   */
  public List<String> getEntries() {
    return Collections.unmodifiableList(accepted);
  }

  /**
   * @param address the remote address of a request
   * @return true when the address is in one of the configured entries
   */
  public boolean matches(String address) {
    if (ranges.isEmpty() || !isClientAddress(address)) {
      return false;
    }
    byte[] bytes = toBytes(normalizeClientAddress(address));
    BigInteger value = new BigInteger(1, bytes);
    return ranges.stream().anyMatch(r -> r.length == bytes.length && r.low.compareTo(value) <= 0 && r.high.compareTo(value) >= 0);
  }

  /**
   * @param address the remote address of a request
   * @return true when the address is an IPv4 or IPv6 literal, once a port, the
   *         brackets of an IPv6 address or a zone are removed. A reverse proxy
   *         may put them in the X-Forwarded-For value that Tomcat copies
   */
  public static boolean isClientAddress(String address) {
    return isLiteral(normalizeClientAddress(address));
  }

  static String normalizeClientAddress(String address) {
    if (address == null) {
      return null;
    }
    String value = address.trim();
    if (value.startsWith("[")) {
      // [IPv6] or [IPv6]:port
      int end = value.indexOf(']');
      value = end > 0 ? value.substring(1, end) : value;
    } else if (value.indexOf(':') == value.lastIndexOf(':') && value.indexOf('.') > 0 && value.indexOf(':') > 0) {
      // IPv4:port
      value = value.substring(0, value.indexOf(':'));
    }
    int zone = value.indexOf('%');
    return zone > 0 ? value.substring(0, zone) : value;
  }

  private static Range parse(String entry) {
    int slash = entry.indexOf('/');
    int dash = entry.indexOf('-');
    if (slash > 0) {
      String host = entry.substring(0, slash);
      byte[] base = toBytes(host);
      int bits = base.length * 8;
      int prefix;
      try {
        prefix = Integer.parseInt(entry.substring(slash + 1));
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("invalid prefix length");
      }
      if (host.indexOf(':') >= 0 && base.length == 4) {
        // An IPv4-mapped IPv6 address is an IPv4 address: its prefix counts the 96 leading bits
        if (prefix < 96) {
          throw new IllegalArgumentException("the prefix of an IPv4-mapped IPv6 address is at least 96");
        }
        prefix -= 96;
      }
      if (prefix < 0 || prefix > bits) {
        throw new IllegalArgumentException("prefix length out of range");
      }
      BigInteger hostMask = BigInteger.ONE.shiftLeft(bits - prefix).subtract(BigInteger.ONE);
      BigInteger low = new BigInteger(1, base).andNot(hostMask);
      return new Range(base.length, low, low.or(hostMask));
    } else if (dash > 0) {
      byte[] low = toBytes(entry.substring(0, dash));
      byte[] high = toBytes(entry.substring(dash + 1));
      if (low.length != high.length) {
        throw new IllegalArgumentException("range mixes IPv4 and IPv6");
      }
      BigInteger lowValue = new BigInteger(1, low);
      BigInteger highValue = new BigInteger(1, high);
      if (lowValue.compareTo(highValue) > 0) {
        throw new IllegalArgumentException("range start is after its end");
      }
      return new Range(low.length, lowValue, highValue);
    }
    byte[] single = toBytes(entry);
    BigInteger value = new BigInteger(1, single);
    return new Range(single.length, value, value);
  }

  private static byte[] toBytes(String literal) {
    if (!isLiteral(literal)) {
      throw new IllegalArgumentException("not an IP address literal");
    }
    try {
      // A validated literal never triggers a DNS lookup. IPv4-mapped IPv6
      // addresses are returned as IPv4 addresses
      return InetAddress.getByName(literal).getAddress();
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("not an IP address literal");
    }
  }

  /**
   * Strict syntax check, done before any {@link InetAddress} call: a string
   * that is not a valid literal would be taken for a host name and sent to the
   * resolver.
   *
   * @param value a candidate IPv4 or IPv6 address
   * @return true when the value is a well-formed IPv4 or IPv6 literal
   */
  static boolean isLiteral(String value) {
    if (value == null || value.isEmpty()) {
      return false;
    }
    if (value.indexOf(':') < 0) {
      return IPV4_LITERAL.matcher(value).matches();
    }
    try {
      // The URI parser accepts only a well-formed IPv6 reference in brackets
      new URI("http://[" + value + "]/");
      return value.indexOf('%') < 0 && value.indexOf(']') < 0;
    } catch (URISyntaxException e) {
      return false;
    }
  }

  private record Range(int length, BigInteger low, BigInteger high) {
  }

}
