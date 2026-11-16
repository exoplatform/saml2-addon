package org.exoplatform.addons.saml.extensions;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;

/**
 * Test-only resolver that records every host name sent to the resolver, then
 * delegates to the built-in one. It lets a test prove that no string is ever
 * resolved.
 */
public class RecordingResolverProvider extends InetAddressResolverProvider {

  public static final List<String> LOOKUPS = new CopyOnWriteArrayList<>();

  @Override
  public InetAddressResolver get(Configuration configuration) {
    InetAddressResolver builtin = configuration.builtinResolver();
    return new InetAddressResolver() {
      @Override
      public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy) throws UnknownHostException {
        LOOKUPS.add(host);
        return builtin.lookupByName(host, lookupPolicy);
      }

      @Override
      public String lookupByAddress(byte[] addr) throws UnknownHostException {
        return builtin.lookupByAddress(addr);
      }
    };
  }

  @Override
  public String name() {
    return "recording-resolver-for-tests";
  }

}
