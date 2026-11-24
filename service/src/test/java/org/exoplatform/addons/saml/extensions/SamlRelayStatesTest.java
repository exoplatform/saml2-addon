package org.exoplatform.addons.saml.extensions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ObjectParameter;
import org.exoplatform.services.cache.ExoCacheConfig;
import org.exoplatform.services.cache.CacheService;
import org.exoplatform.services.cache.impl.CacheServiceImpl;

public class SamlRelayStatesTest {

  /** A real cache service of the kernel, with a default configuration (600 seconds) for its caches. */
  static CacheService realCacheService() {
    try {
      ExoCacheConfig config = new ExoCacheConfig();
      config.setName("default");
      config.setMaxSize(100);
      config.setLiveTime(600);
      config.setImplementation("org.exoplatform.services.cache.concurrent.ConcurrentFIFOExoCache");
      ObjectParameter parameter = new ObjectParameter();
      parameter.setName("default");
      parameter.setObject(config);
      InitParams params = new InitParams();
      params.addParameter(parameter);
      return new CacheServiceImpl(params);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private final CacheService   cacheService = realCacheService();

  private final SamlRelayStates states      = new SamlRelayStates(() -> cacheService);

  private static SamlRelayTarget target(String uri, String query) {
    return new SamlRelayTarget(uri, uri, query);
  }

  @Test
  public void aTargetIsGivenBackByItsIdOnce() {
    SamlRelayTarget target = target("/portal/sso", "initialURI=/portal/g/:spaces:x");

    String id = states.put(target);

    assertEquals(target, states.take(id));
    assertNull(states.take(id));
  }

  @Test
  public void theTargetLivesInTheCacheOfThePortalUnderItsDeclaredName() {
    String id = states.put(target("/portal/sso", null));

    assertNotNull(cacheService.getCacheInstance(SamlRelayStates.CACHE_NAME).get(id));
  }

  @Test
  public void theIdFitsInTheRelayStateOfTheSpecification() {
    String id = states.put(target("/portal/sso", null));

    assertTrue(id.length() <= 80);
    assertTrue(id.matches("[A-Za-z0-9_-]+"));
    assertNotEquals(id, states.put(target("/portal/sso", null)));
  }

  @Test
  public void anUnknownOrMalformedIdGivesNothing() {
    states.put(target("/portal/sso", null));

    assertNull(states.take("unknown"));
    assertNull(states.take(""));
    assertNull(states.take(null));
    assertNull(states.take("x".repeat(65)));
  }

  @Test
  public void withoutACacheServiceNothingIsKept() {
    SamlRelayStates withoutCache = new SamlRelayStates(() -> null);

    assertNull(withoutCache.put(target("/portal/sso", null)));
    assertNull(withoutCache.take("anything"));
  }

  @Test
  public void aCacheThatFailsDoesNotBreakTheSignIn() {
    SamlRelayStates failing = new SamlRelayStates(() -> {
      throw new IllegalStateException("cache down");
    });

    assertNull(failing.put(target("/portal/sso", null)));
    assertNull(failing.take("anything"));
  }

  @Test
  public void aPathOfTheApplicationIsATarget() {
    assertTrue(SamlRelayStates.isTargetOfThisApplication("/portal", target("/portal/sso", "initialURI=/portal/g/:spaces:x")));
    assertTrue(SamlRelayStates.isTargetOfThisApplication("/portal", target("/portal", null)));
    assertTrue(SamlRelayStates.isTargetOfThisApplication("", target("/", null)));
  }

  @Test
  public void anAddressThatLeavesTheApplicationIsNotATarget() {
    for (String uri : new String[] { "//evil.example/portal", "/\\evil.example", "https://evil.example/portal", "evil.example",
        "/portalx/sso", "/other/sso", "/portal/../admin", "/portal/%2e%2e/admin", "/portal/%2E./admin", "/portal/a%2fb",
        "/portal/a%5Cb", "/portal/a\r\nSet-Cookie: x=1", "/portal/\u0000", null, "/portal/" + "a".repeat(2048) }) {
      assertFalse(SamlRelayStates.isTargetOfThisApplication("/portal", target(uri, null)), String.valueOf(uri));
    }
    assertFalse(SamlRelayStates.isTargetOfThisApplication("/portal", target("/portal/sso", "a=b\r\nc")));
    assertFalse(SamlRelayStates.isTargetOfThisApplication("/portal", target("/portal/sso", "a".repeat(2049))));
    assertFalse(SamlRelayStates.isTargetOfThisApplication("/portal", null));
    assertFalse(SamlRelayStates.isTargetOfThisApplication(null, target("/portal/sso", null)));
  }

}
