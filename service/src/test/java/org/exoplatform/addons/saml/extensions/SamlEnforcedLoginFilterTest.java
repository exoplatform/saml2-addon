package org.exoplatform.addons.saml.extensions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class SamlEnforcedLoginFilterTest {

  /** The real filter, initialised through initImpl() with the given init parameters */
  private SamlEnforcedLoginFilter filter(String ips, String suffix) {
    Map<String, String> params = new java.util.HashMap<>();
    params.put("ENFORCED_IPS", ips);
    params.put("SSO_URL_SUFFIX", suffix);
    SamlEnforcedLoginFilter filter = new SamlEnforcedLoginFilter() {
      @Override
      public String getInitParameter(String name) {
        return params.get(name);
      }
    };
    filter.initImpl();
    return filter;
  }

  private HttpServletRequest request(String remoteAddr, String path, String remoteUser, String query) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRemoteAddr()).thenReturn(remoteAddr);
    when(request.getServletPath()).thenReturn(path);
    when(request.getRemoteUser()).thenReturn(remoteUser);
    when(request.getContextPath()).thenReturn("/portal");
    when(request.getRequestURI()).thenReturn("/portal" + path);
    ServletContext servletContext = mock(ServletContext.class);
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(request.getServletContext()).thenReturn(servletContext);
    when(request.getQueryString()).thenReturn(query);
    return request;
  }

  private HttpServletResponse response() {
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(response.encodeRedirectURL(anyString())).thenAnswer(i -> i.getArgument(0));
    return response;
  }

  private void assertRedirected(SamlEnforcedLoginFilter filter, HttpServletRequest request, String expected) throws Exception {
    HttpServletResponse response = response();
    FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);
    verify(response).sendRedirect(expected);
    verify(chain, never()).doFilter(any(), any());
  }

  private ServletRequest passedOn(SamlEnforcedLoginFilter filter, HttpServletRequest request) throws Exception {
    HttpServletResponse response = response();
    FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);
    verify(response, never()).sendRedirect(anyString());
    ArgumentCaptor<ServletRequest> passed = ArgumentCaptor.forClass(ServletRequest.class);
    verify(chain).doFilter(passed.capture(), any());
    return passed.getValue();
  }

  @Test
  public void everyRouteOfTheLoginHandlerThatTakesAPasswordIsRedirected() throws Exception {
    SamlEnforcedLoginFilter filter = filter("10.0.0.0/8", null);
    for (String path : new String[] { "/login", "/login/", "/doLogin", "/doLogin/", "/dologin/" }) {
      assertRedirected(filter,
                       request("10.2.3.4", path, null, "initialURI=/portal/g/:spaces:x"),
                       "/portal/sso?initialURI=/portal/g/:spaces:x");
    }
  }

  @Test
  public void redirectWithoutQueryStringAndWithACustomSuffix() throws Exception {
    assertRedirected(filter("10.0.0.0/8", " /saml "), request("10.2.3.4", "/login", null, null), "/portal/saml");
  }

  @Test
  public void theSamlValveUrlIsNeverRedirected() throws Exception {
    // /dologin starts the SAML workflow: redirecting it to /sso would loop
    HttpServletRequest request = request("10.2.3.4", "/dologin", null, null);
    HttpServletRequest passed = (HttpServletRequest) passedOn(filter("10.0.0.0/8", null), request);
    assertEquals("/dologin", passed.getServletPath());
  }

  @Test
  public void theRedirectUsesTheContextPathOfTheServletContext() throws Exception {
    // The raw context path of the request is shaped by the client
    HttpServletRequest request = request("10.2.3.4", "/login", null, null);
    when(request.getContextPath()).thenReturn("/./evil.com/..;/portal");
    assertRedirected(filter("10.0.0.0/8", null), request, "/portal/sso");
  }

  @Test
  public void aRouteThatOnlyTheRouterSeesIsRedirected() throws Exception {
    // With a Tomcat that lets encoded slashes through, the servlet path is /login%2F
    // and the portal router decodes the URI to the route /login/
    HttpServletRequest request = request("10.2.3.4", "/login%2F", null, null);
    when(request.getRequestURI()).thenReturn("/portal/login%2F");
    assertRedirected(filter("10.0.0.0/8", null), request, "/portal/sso");
    HttpServletRequest other = request("10.2.3.4", "/dologin%2f", null, null);
    when(other.getRequestURI()).thenReturn("/portal/dologin%2f");
    assertRedirected(filter("10.0.0.0/8", null), other, "/portal/sso");
    HttpServletRequest sso = request("10.2.3.4", "/sso", null, null);
    when(sso.getRequestURI()).thenReturn("/portal/sso");
    assertNotNull(passedOn(filter("10.0.0.0/8", null), sso));
  }

  @Test
  public void theLogoutKeepsTheRememberMeCookieSoThatThePortalCanRevokeItsToken() throws Exception {
    HttpServletRequest request = request("10.2.3.4", "/logout", null, null);
    when(request.getCookies()).thenReturn(new Cookie[] { new Cookie("rememberme", "token") });
    ServletRequest passed = passedOn(filter("10.0.0.0/8", null), request);
    assertSame(request, passed);
    assertEquals(1, ((HttpServletRequest) passed).getCookies().length);
  }

  @Test
  public void aLogoutThatThePortalRouterDoesNotSeeAsTheLogoutDoesNotKeepTheCookie() throws Exception {
    // Tomcat strips ;x=1 from the servlet path, the portal router routes on the request URI
    for (String uri : new String[] { "/portal/logout;x=1", "/portal//logout", "/portal/logout/", "/portal/logout%3Bx=1" }) {
      HttpServletRequest request = request("10.2.3.4", "/logout", null, null);
      when(request.getRequestURI()).thenReturn(uri);
      when(request.getCookies()).thenReturn(new Cookie[] { new Cookie("rememberme", "token"), new Cookie("JSESSIONID", "1") });
      Cookie[] seen = ((HttpServletRequest) passedOn(filter("10.0.0.0/8", null), request)).getCookies();
      assertEquals(1, seen.length, uri);
      assertEquals("JSESSIONID", seen[0].getName(), uri);
    }
  }

  @Test
  public void aBlankSsoSuffixKeepsTheDefault() throws Exception {
    assertRedirected(filter("10.0.0.0/8", "  "), request("10.2.3.4", "/login", null, null), "/portal/sso");
  }

  @Test
  public void aMalformedEncodingOfTheUriIsTreatedAsALoginRoute() throws Exception {
    HttpServletRequest request = request("10.2.3.4", "/anything", null, null);
    when(request.getRequestURI()).thenReturn("/portal/login%");
    assertRedirected(filter("10.0.0.0/8", null), request, "/portal/sso");
  }

  @Test
  public void aMalformedEncodingIsNotTheLogout() {
    HttpServletRequest request = request("10.2.3.4", "/logout", null, null);
    when(request.getRequestURI()).thenReturn("/portal/logout%");
    assertFalse(SamlEnforcedLoginFilter.isLogoutRoute(request));
  }

  @Test
  public void aUriOutsideTheContextPathIsNeitherARouteNorTheLogout() throws Exception {
    for (String uri : new String[] { null, "/elsewhere/login" }) {
      HttpServletRequest request = request("10.2.3.4", "/logout", null, null);
      when(request.getRequestURI()).thenReturn(uri);
      assertFalse(SamlEnforcedLoginFilter.isLogoutRoute(request));
    }
    HttpServletRequest noContext = request("10.2.3.4", "/logout", null, null);
    when(noContext.getContextPath()).thenReturn(null);
    assertFalse(SamlEnforcedLoginFilter.isLogoutRoute(noContext));
    assertFalse(SamlEnforcedLoginFilter.isLoginRoute(noContext));
  }

  @Test
  public void destroyHasNothingToRelease() {
    filter("10.0.0.0/8", null).destroy();
  }

  @Test
  public void aClientThatIsNotListedIsNeverTouched() throws Exception {
    HttpServletRequest request = request("192.168.1.1", "/login", null, null);
    assertSame(request, passedOn(filter("10.0.0.0/8", null), request));
    HttpServletRequest other = request("192.168.1.1", "/portal/dw", null, null);
    assertSame(other, passedOn(filter("10.0.0.0/8", null), other));
  }

  @Test
  public void anAuthenticatedUserIsNeverTouched() throws Exception {
    HttpServletRequest request = request("10.2.3.4", "/login", "root", null);
    assertSame(request, passedOn(filter("10.0.0.0/8", null), request));
  }

  @Test
  public void anEmptyListEnforcesNobody() throws Exception {
    for (String ips : new String[] { null, "", "  ", "not-an-ip" }) {
      HttpServletRequest request = request("10.2.3.4", "/login", null, null);
      assertSame(request, passedOn(filter(ips, null), request));
    }
  }

  @Test
  public void theRememberMeCookieOfAnEnforcedClientIsHidden() throws Exception {
    HttpServletRequest request = request("10.2.3.4", "/portal/dw", null, null);
    Cookie remember = new Cookie("rememberme", "token");
    Cookie session = new Cookie("JSESSIONID", "abc");
    when(request.getCookies()).thenReturn(new Cookie[] { session, remember });

    Cookie[] seen = ((HttpServletRequest) passedOn(filter("10.0.0.0/8", null), request)).getCookies();

    assertEquals(1, seen.length);
    assertEquals("JSESSIONID", seen[0].getName());
  }

  @Test
  public void aRequestWithoutCookiesIsHandled() throws Exception {
    HttpServletRequest request = request("10.2.3.4", "/portal/dw", null, null);
    assertNull(((HttpServletRequest) passedOn(filter("10.0.0.0/8", null), request)).getCookies());
  }

  @Test
  public void theRememberMeCookieOfAClientThatIsNotListedIsKept() throws Exception {
    HttpServletRequest request = request("192.168.1.1", "/portal/dw", null, null);
    Cookie remember = new Cookie("rememberme", "token");
    when(request.getCookies()).thenReturn(new Cookie[] { remember });
    assertEquals(1, ((HttpServletRequest) passedOn(filter("10.0.0.0/8", null), request)).getCookies().length);
  }

  @Test
  public void theForwardedForHeaderIsNeverRead() throws Exception {
    // The remote address is outside the list, the header claims to be inside it
    HttpServletRequest request = request("192.168.1.1", "/login", null, null);
    when(request.getHeader("X-Forwarded-For")).thenReturn("10.2.3.4");
    assertSame(request, passedOn(filter("10.0.0.0/8", null), request));
    verify(request, never()).getHeader("X-Forwarded-For");
    verify(request, never()).getHeaders("X-Forwarded-For");
  }

  @Test
  public void anAddressWithAPortIsStillMatched() throws Exception {
    // Some reverse proxies put ip:port or [ipv6]:port in the header that Tomcat copies
    assertRedirected(filter("10.0.0.0/8, 2001:db8::/32", null), request("10.2.3.4:51234", "/login", null, null), "/portal/sso");
    assertRedirected(filter("10.0.0.0/8, 2001:db8::/32", null),
                     request("[2001:db8::7]:51234", "/login", null, null),
                     "/portal/sso");
  }

  @Test
  public void anAddressThatCannotBeParsedIsEnforced() throws Exception {
    for (String address : new String[] { "unknown", "", "999.1.1.1", "10.2.3.4, 10.5.6.7" }) {
      assertRedirected(filter("10.0.0.0/8", null), request(address, "/login", null, null), "/portal/sso");
    }
    assertRedirected(filter("10.0.0.0/8", null), request(null, "/login", null, null), "/portal/sso");
  }

  @Test
  public void aSpacedRangeInTheListIsEnforced() throws Exception {
    assertRedirected(filter("172.16.5.1 - 172.16.5.50", null), request("172.16.5.20", "/login", null, null), "/portal/sso");
  }

}
