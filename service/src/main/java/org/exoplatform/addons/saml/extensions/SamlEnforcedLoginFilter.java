package org.exoplatform.addons.saml.extensions;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

import org.gatein.sso.agent.filter.api.AbstractSSOInterceptor;

import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.web.login.LoginUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

/**
 * When the portal login page is kept next to the SAML login (see
 * {@link SamlLoginParamsExtension}), this filter enforces the SAML login for
 * the clients whose IP address is listed in
 * {@code gatein.sso.saml.login.enforced.ips}. It only acts on anonymous
 * requests of those clients:
 * <ul>
 * <li>a request to a route of the portal login handler that takes a local
 * password ({@code /login}, {@code /doLogin}, and {@code /dologin/} which is
 * not the constrained URL of the SAML valve) is redirected to the SSO URL, as
 * when the portal login page is not kept;</li>
 * <li>on any other request but the logout, the remember-me cookie of a local
 * login is hidden from the portal web application, so that the portal's
 * remember-me filter does not sign the client in without SAML.</li>
 * </ul>
 * The client address is {@link HttpServletRequest#getRemoteAddr()}. The
 * {@code X-Forwarded-For} header is never read here because a client can
 * forge it: behind a reverse proxy, configure the Tomcat RemoteIpValve so that
 * the remote address is the real client one, and trust only your proxies
 * ({@code internalProxies}). An address that cannot be parsed is enforced.
 * <p>
 * Not covered, because they are other web applications or other login modules
 * that read the raw request: the HTTP Basic and Digest authentication of the
 * REST and WebDAV web applications (which also give a portal session through
 * Tomcat's single sign-on valve, and in which the JAAS remember-me login
 * module still honours a remember-me cookie sent with any password), and the
 * remember-me cookie on the REST endpoints of the Spring-based web
 * applications.
 */
public class SamlEnforcedLoginFilter extends AbstractSSOInterceptor {

  private static final Log     LOG          = ExoLogger.getLogger(SamlEnforcedLoginFilter.class);

  /**
   * The routes of the login handler that log in with a username and a
   * password. Not {@code /dologin}: it is the constrained URL that the SAML
   * valve intercepts to start the SAML workflow
   */
  static final Pattern         LOGIN_ROUTES = Pattern.compile("/(login|doLogin)/?|/dologin/");

  /**
   * The logout route: the portal deletes the remember-me token of its cookie
   * there, even for an anonymous request, so the cookie must stay visible
   */
  static final String          LOGOUT_ROUTE = "/logout";

  private IpMatcher            enforcedIps  = new IpMatcher(null);

  private String               ssoUrlSuffix = "/sso";

  @Override
  protected void initImpl() {
    this.enforcedIps = new IpMatcher(getInitParameter("ENFORCED_IPS"));
    String suffix = getInitParameter("SSO_URL_SUFFIX");
    if (suffix != null && !suffix.isBlank()) {
      this.ssoUrlSuffix = suffix.trim();
    }
    LOG.info("SAML login enforced for the client addresses: {}", enforcedIps.isEmpty() ? "none" : enforcedIps.getEntries());
  }

  @Override
  public void doFilter(ServletRequest servletRequest,
                       ServletResponse servletResponse,
                       FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    if (request.getRemoteUser() != null || enforcedIps.isEmpty() || !isEnforced(request)) {
      filterChain.doFilter(servletRequest, servletResponse);
    } else if (isLoginRoute(request)) {
      // The context path of the servlet context, not the raw one of the request, which the client shapes
      String url = request.getServletContext().getContextPath() + ssoUrlSuffix;
      if (request.getQueryString() != null) {
        url += "?" + request.getQueryString();
      }
      HttpServletResponse response = (HttpServletResponse) servletResponse;
      response.sendRedirect(response.encodeRedirectURL(url));
    } else if (isLogoutRoute(request)) {
      filterChain.doFilter(servletRequest, servletResponse);
    } else {
      filterChain.doFilter(new WithoutRememberMeCookie(request), servletResponse);
    }
  }

  /**
   * The portal router decodes the request URI itself, which the servlet path
   * is not: with a Tomcat that lets encoded slashes through, /login%2F is the
   * servlet path /login%2F and the route /login/. Both views are checked
   *
   * @param request current request
   * @return true when the request goes to a route of the login handler that
   *         takes a local password
   */
  static boolean isLoginRoute(HttpServletRequest request) {
    if (LOGIN_ROUTES.matcher(request.getServletPath()).matches()) {
      return true;
    }
    try {
      String routed = routedPath(request);
      return routed != null && LOGIN_ROUTES.matcher(routed).matches();
    } catch (IllegalArgumentException e) {
      // A malformed encoding is never a route of the login handler, but it is not worth a risk either
      return true;
    }
  }

  /**
   * Tomcat strips the path parameters ({@code /logout;x=1}) before it maps the
   * servlet path, which the portal router does not: it routes on the request
   * URI, and {@code logout;x=1} is not the logout route, so the portal never
   * revokes the remember-me token and its remember-me filter signs the client
   * in. The logout keeps the cookie only when both views agree. Otherwise the
   * cookie is hidden, which fails safe: the logout then runs anonymous.
   *
   * @param request current request
   * @return true when the servlet path and the routed path are both the logout
   */
  static boolean isLogoutRoute(HttpServletRequest request) {
    if (!LOGOUT_ROUTE.equals(request.getServletPath())) {
      return false;
    }
    try {
      return LOGOUT_ROUTE.equals(routedPath(request));
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * @param request current request
   * @return the percent-decoded request URI minus the context path, which is
   *         what the portal router sees, or null when the URI is not under the
   *         context path
   * @throws IllegalArgumentException when the encoding is malformed
   */
  private static String routedPath(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String contextPath = request.getContextPath();
    if (uri == null || contextPath == null || !uri.startsWith(contextPath)) {
      return null;
    }
    return URLDecoder.decode(uri.substring(contextPath.length()).replace("+", "%2B"), StandardCharsets.UTF_8);
  }

  protected boolean isEnforced(HttpServletRequest request) {
    String address = request.getRemoteAddr();
    return enforcedIps.matches(address) || !IpMatcher.isClientAddress(address);
  }

  @Override
  public void destroy() {
    // Nothing to destroy
  }

  /**
   * Hides the remember-me cookie of the portal local login, which the portal
   * reads with {@code getCookies()}
   */
  static class WithoutRememberMeCookie extends HttpServletRequestWrapper {

    WithoutRememberMeCookie(HttpServletRequest request) {
      super(request);
    }

    @Override
    public Cookie[] getCookies() {
      Cookie[] cookies = super.getCookies();
      return cookies == null ? null : Arrays.stream(cookies).filter(c -> !LoginUtils.COOKIE_NAME.equals(c.getName())).toArray(Cookie[]::new);
    }

  }

}
