package org.exoplatform.addons.saml.extensions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Pins the registration of the enforcement filter in the real kernel
 * configuration, and the login routes it redirects.
 */
public class SamlEnforcedLoginMappingTest {

  private static String pluginParam(String name) throws Exception {
    try (InputStream in = SamlEnforcedLoginMappingTest.class.getResourceAsStream("/conf/portal/configuration.xml")) {
      assertNotNull(in);
      Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
      NodeList plugins = doc.getElementsByTagName("component-plugin");
      for (int i = 0; i < plugins.getLength(); i++) {
        Element plugin = (Element) plugins.item(i);
        if ("SamlEnforcedLoginFilter".equals(plugin.getElementsByTagName("name").item(0).getTextContent())) {
          NodeList params = plugin.getElementsByTagName("value-param");
          for (int j = 0; j < params.getLength(); j++) {
            Element param = (Element) params.item(j);
            if (name.equals(param.getElementsByTagName("name").item(0).getTextContent())) {
              return param.getElementsByTagName("value").item(0).getTextContent().trim();
            }
          }
        }
      }
    }
    throw new AssertionError("SamlEnforcedLoginFilter plugin or its parameter " + name + " not found");
  }

  @Test
  public void theFilterSeesEveryRequestAndIsEnabledOnlyByTheFlag() throws Exception {
    // The remember-me cookie must be hidden on every path, not only on the login routes
    assertEquals("/*", pluginParam("filterMapping"));
    assertEquals("${gatein.sso.saml.login.page.enabled:false}", pluginParam("enabled"));
    assertEquals("${gatein.sso.saml.login.enforced.ips:}", pluginParam("ENFORCED_IPS"));
    assertEquals(SamlEnforcedLoginFilter.class.getName(), pluginParam("filterClass"));
  }

  @Test
  public void everyRouteOfTheLoginHandlerThatTakesAPasswordIsCovered() {
    // /login and /doLogin are routes of the login handler (controller.xml), and so is /dologin: its
    // constrained form is the SAML valve's, but the form with a trailing slash is not constrained
    for (String path : new String[] { "/login", "/login/", "/doLogin", "/doLogin/", "/dologin/" }) {
      assertTrue(SamlEnforcedLoginFilter.LOGIN_ROUTES.matcher(path).matches(), path);
    }
  }

  @Test
  public void theSamlValveUrlAndOtherPathsAreNotLoginRoutes() {
    // /dologin is the SAML valve's constrained URL: redirecting it to /sso would loop
    for (String path : new String[] { "/dologin", "/sso", "/logout", "/login-help", "/login/x", "/LOGIN", "/rest/private/x/login",
                                      "" }) {
      assertFalse(SamlEnforcedLoginFilter.LOGIN_ROUTES.matcher(path).matches(), path);
    }
  }

}
