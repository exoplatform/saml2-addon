package org.exoplatform.addons.saml.extensions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;
import org.exoplatform.web.ControllerContext;
import org.exoplatform.web.login.LoginHandler;
import org.exoplatform.web.security.sso.SSOHelper;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;

public class SamlLoginParamsExtensionTest {

  private ExoContainer previousContainer;

  @BeforeEach
  public void setUp() {
    previousContainer = ExoContainerContext.getCurrentContainerIfPresent();
  }

  @AfterEach
  public void tearDown() {
    ExoContainerContext.setCurrentContainer(previousContainer);
  }

  /** The portal container of the current thread, whose web application is mounted on the given path */
  private static void currentPortalContainer(String contextPath) {
    ServletContext portalContext = mock(ServletContext.class);
    when(portalContext.getContextPath()).thenReturn(contextPath);
    PortalContainer container = mock(PortalContainer.class);
    when(container.getPortalContext()).thenReturn(portalContext);
    ExoContainerContext.setCurrentContainer(container);
  }

  private static InitParams params(String enabled) {
    InitParams params = new InitParams();
    if (enabled != null) {
      ValueParam param = new ValueParam();
      param.setName("enabled");
      param.setValue(enabled);
      params.addParam(param);
    }
    return params;
  }

  private static SSOHelper sso(boolean enabled) {
    SSOHelper helper = mock(SSOHelper.class);
    when(helper.isSSOEnabled()).thenReturn(enabled);
    when(helper.getSSORedirectURLSuffix()).thenReturn("/sso");
    return helper;
  }

  private static ControllerContext context() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    // The context path of the servlet context, not the raw one of the request, which the client shapes
    // The login page is rendered by the social web application: its servlet context is not the portal one
    ServletContext servletContext = mock(ServletContext.class);
    when(servletContext.getContextPath()).thenReturn("/social");
    when(request.getServletContext()).thenReturn(servletContext);
    when(request.getContextPath()).thenReturn("/./evil.com/..;/portal");
    ControllerContext context = mock(ControllerContext.class);
    when(context.getRequest()).thenReturn(request);
    return context;
  }

  @Test
  public void extendsTheLoginPage() {
    currentPortalContainer("/portal");
    SamlLoginParamsExtension extension = new SamlLoginParamsExtension(sso(true), params("true"));
    assertEquals(java.util.List.of(LoginHandler.LOGIN_EXTENSION_NAME), extension.getExtensionNames());

    Map<String, Object> result = extension.extendParameters(context(), LoginHandler.LOGIN_EXTENSION_NAME);

    assertEquals(true, result.get("samlLoginEnabled"));
    assertEquals("/portal/sso", result.get("samlLoginUrl"));
    assertEquals("saml", result.get("extendedAuthProviderType"));
  }

  @Test
  public void theSsoUriSuffixOfThePortalIsUsed() {
    SSOHelper helper = sso(true);
    when(helper.getSSORedirectURLSuffix()).thenReturn("/enter");
    currentPortalContainer("/portal");
    Map<String, Object> result = new SamlLoginParamsExtension(helper, params("true")).extendParameters(context(),
                                                                                                       LoginHandler.LOGIN_EXTENSION_NAME);
    assertEquals("/portal/enter", result.get("samlLoginUrl"));
  }

  /** The login page is rendered by the social web application: its servlet context ("/social") is not the portal's */
  @Test
  public void theUrlIsOnThePortalWebApplicationNotOnTheOneThatRendersThePage() {
    currentPortalContainer("/portal");
    Map<String, Object> result = new SamlLoginParamsExtension(sso(true), params("true")).extendParameters(context(),
                                                                                                          LoginHandler.LOGIN_EXTENSION_NAME);
    assertEquals("/portal/sso", result.get("samlLoginUrl"));
  }

  /** Without a current portal container the servlet context of the request is the only path left */
  @Test
  public void withoutAPortalContainerTheServletContextOfTheRequestIsUsed() {
    ExoContainerContext.setCurrentContainer(null);
    Map<String, Object> result = new SamlLoginParamsExtension(sso(true), params("true")).extendParameters(context(),
                                                                                                          LoginHandler.LOGIN_EXTENSION_NAME);
    assertEquals("/social/sso", result.get("samlLoginUrl"));
  }

  @Test
  public void aSkippedLoginPageOnlyWarns() {
    SSOHelper helper = sso(true);
    when(helper.skipJSPRedirection()).thenReturn(true);
    // The button is still offered: the warning tells the administrator that the login page is not displayed
    currentPortalContainer("/portal");
    assertEquals(true,
                 new SamlLoginParamsExtension(helper, params("true")).extendParameters(context(), LoginHandler.LOGIN_EXTENSION_NAME)
                                                                     .get("samlLoginEnabled"));
  }

  @Test
  public void nothingIsAddedWithoutTheFlag() {
    for (InitParams params : new InitParams[] { params("false"), params(""), params("yes"), params(null), null }) {
      assertNull(new SamlLoginParamsExtension(sso(true), params).extendParameters(context(), LoginHandler.LOGIN_EXTENSION_NAME));
    }
  }

  @Test
  public void nothingIsAddedWhenSsoIsDisabled() {
    assertNull(new SamlLoginParamsExtension(sso(false), params("true")).extendParameters(context(), LoginHandler.LOGIN_EXTENSION_NAME));
  }

}
