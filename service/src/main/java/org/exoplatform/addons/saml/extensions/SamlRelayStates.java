package org.exoplatform.addons.saml.extensions;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import org.exoplatform.services.cache.CacheService;
import org.exoplatform.services.cache.ExoCache;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

/**
 * Keeps the page a user asked for while they are at the IDP, under an opaque id
 * that travels as the SAML {@code RelayState}.
 * <p>
 * The session cannot keep it when the IDP and the SP are not on the same site:
 * the IDP answers with a cross-site POST, a {@code SameSite=Lax} session cookie
 * is not sent with it and the session is a new one. The id is echoed by the IDP
 * in that POST, whatever the cookies.
 * <p>
 * The pages live in the {@value #CACHE_NAME} cache of the portal, which this
 * add-on declares in {@code conf/portal/configuration.xml}: 10,000 entries for
 * 600 seconds, replicated under the {@code cluster} profile, because the answer
 * of the IDP, sent without the session cookie, can reach another node. Without
 * a cache service nothing is kept and the user lands on the default page, as
 * with the stock valve.
 */
class SamlRelayStates {

  /** Name of the cache of the portal that keeps the pages. */
  static final String          CACHE_NAME    = "saml.relaystate";

  /** Longest accepted request URI and query string. */
  static final int             MAX_LENGTH    = 2048;

  private static final Log     LOG           = ExoLogger.getLogger(SamlRelayStates.class);

  private static final int     ID_BYTES      = 16;

  private static final int     MAX_ID_LENGTH = 64;

  private static final char    FIRST_PRINTABLE = 0x20;

  private static final char    DELETE        = 0x7f;

  private final SecureRandom   random        = new SecureRandom();

  private final AtomicBoolean  warned        = new AtomicBoolean();

  private final Supplier<CacheService> cacheServices;

  /**
   * Creates the store.
   *
   * @param cacheServices gives the cache service of the portal, or null
   */
  SamlRelayStates(Supplier<CacheService> cacheServices) {
    this.cacheServices = cacheServices;
  }

  /**
   * Keeps a target.
   *
   * @param target what to keep
   * @return the id to send as RelayState, or null when it could not be kept
   */
  String put(SamlRelayTarget target) {
    try {
      ExoCache<String, SamlRelayTarget> cache = cache();
      if (cache != null) {
        byte[] bytes = new byte[ID_BYTES];
        random.nextBytes(bytes);
        String id = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        cache.put(id, target);
        return id;
      }
    } catch (RuntimeException e) {
      LOG.warn("The page asked for before the SAML sign-in could not be kept in the cache {}: {}", CACHE_NAME, e.getMessage());
    }
    return null;
  }

  /**
   * Gives a target and forgets it: an id is good for one use.
   *
   * @param id the id given by {@link #put(SamlRelayTarget)}
   * @return the target, or null when the id is unknown or has expired
   */
  SamlRelayTarget take(String id) {
    if (id == null || id.isEmpty() || id.length() > MAX_ID_LENGTH) {
      return null;
    }
    try {
      ExoCache<String, SamlRelayTarget> cache = cache();
      return cache == null ? null : cache.remove(id);
    } catch (RuntimeException e) {
      LOG.warn("The page asked for before the SAML sign-in could not be read from the cache {}: {}", CACHE_NAME, e.getMessage());
      return null;
    }
  }

  /**
   * Tells if a request of this web application can be the target: a path of the
   * context, never an address that sends the browser to another site.
   *
   * @param contextPath the context path of this web application
   * @param target the request to check
   * @return true if the user can be sent to it
   */
  static boolean isTargetOfThisApplication(String contextPath, SamlRelayTarget target) {
    if (target == null || contextPath == null) {
      return false;
    }
    String uri = target.requestURI();
    String query = target.queryString();
    return uri != null && uri.length() <= MAX_LENGTH
        && (query == null || query.length() <= MAX_LENGTH)
        && (uri.equals(contextPath) || uri.startsWith(contextPath + "/"))
        && uri.startsWith("/") && !uri.startsWith("//") && !uri.contains("\\")
        && !hasControlCharacter(uri) && (query == null || !hasControlCharacter(query))
        && !hasDotSegment(uri);
  }

  private static boolean hasControlCharacter(String value) {
    return value.chars().anyMatch(c -> c < FIRST_PRINTABLE || c == DELETE);
  }

  private static boolean hasDotSegment(String uri) {
    for (String segment : uri.split("/", -1)) {
      String decoded = segment.replace("%2e", ".").replace("%2E", ".");
      if (decoded.equals("..") || decoded.equals(".") || segment.contains("%2f") || segment.contains("%2F")
          || segment.contains("%5c") || segment.contains("%5C")) {
        return true;
      }
    }
    return false;
  }

  private ExoCache<String, SamlRelayTarget> cache() {
    CacheService service = cacheServices.get();
    if (service == null) {
      if (warned.compareAndSet(false, true)) {
        LOG.warn("No cache service: the page asked for before the SAML sign-in is not kept, the user lands on the default page");
      }
      return null;
    }
    return service.getCacheInstance(CACHE_NAME);
  }

}
