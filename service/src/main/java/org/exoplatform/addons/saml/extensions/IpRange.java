package org.exoplatform.addons.saml.extensions;

import java.math.BigInteger;

/**
 * An inclusive range of IP addresses of one family, as unsigned integers
 *
 * @param length the address length in bytes: 4 for IPv4, 16 for IPv6
 * @param low the first address of the range
 * @param high the last address of the range
 */
record IpRange(int length, BigInteger low, BigInteger high) {
}
