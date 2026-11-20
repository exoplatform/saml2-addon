package org.exoplatform.addons.saml.extensions;

import java.util.Arrays;

import org.exoplatform.web.login.LoginUtils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * Hides the remember-me cookie of the portal local login, which the portal
 * reads with {@code getCookies()}
 */
class WithoutRememberMeCookie extends HttpServletRequestWrapper {

  WithoutRememberMeCookie(HttpServletRequest request) {
    super(request);
  }

  @Override
  public Cookie[] getCookies() {
    Cookie[] cookies = super.getCookies();
    return cookies == null ? null : Arrays.stream(cookies).filter(c -> !LoginUtils.COOKIE_NAME.equals(c.getName())).toArray(Cookie[]::new);
  }

}
