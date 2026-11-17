package org.exoplatform.addons.saml.extensions;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.web.ControllerContext;
import org.exoplatform.web.login.LoginHandler;
import org.exoplatform.web.login.UIParamsExtension;
import org.exoplatform.web.security.sso.SSOHelper;

import jakarta.servlet.ServletContext;

/**
 * Optional feature: keep the portal login page and offer a "Sign in with SAML"
 * button, instead of redirecting every unauthenticated user to the IDP.
 * Enabled by {@code gatein.sso.saml.login.page.enabled=true}. The portal must
 * also display its login page ({@code gatein.sso.skip.jsp.redirection=false}).
 */
public class SamlLoginParamsExtension implements UIParamsExtension {

  private static final Log LOG                       = ExoLogger.getLogger(SamlLoginParamsExtension.class);

  public static final String ENABLED_PARAM          = "enabled";

  public static final String SAML_LOGIN_ENABLED     = "samlLoginEnabled";

  public static final String SAML_LOGIN_URL         = "samlLoginUrl";

  private final boolean    enabled;

  private final SSOHelper  ssoHelper;

  public SamlLoginParamsExtension(SSOHelper ssoHelper, InitParams params) {
    this.ssoHelper = ssoHelper;
    boolean flag = params != null
        && params.getValueParam(ENABLED_PARAM) != null
        && Boolean.parseBoolean(params.getValueParam(ENABLED_PARAM).getValue());
    this.enabled = flag && ssoHelper.isSSOEnabled();
    if (flag && !ssoHelper.isSSOEnabled()) {
      LOG.warn("gatein.sso.saml.login.page.enabled is true but gatein.sso.enabled is false: SAML login button disabled");
    } else if (flag && ssoHelper.skipJSPRedirection()) {
      LOG.warn("gatein.sso.saml.login.page.enabled is true but the portal login page is skipped: "
          + "set gatein.sso.skip.jsp.redirection=false to display the SAML login button");
    }
  }

  @Override
  public List<String> getExtensionNames() {
    return Collections.singletonList(LoginHandler.LOGIN_EXTENSION_NAME);
  }

  /**
   * The context path of the portal web application, where the SSO URL lives.
   * Not the one of the request: the login page is rendered by another web
   * application (the request then reports its servlet context, /social), and
   * the raw context path of the request is shaped by the client.
   *
   * @param controllerContext current request
   * @return the context path of the portal web application
   */
  String getPortalContextPath(ControllerContext controllerContext) {
    PortalContainer container = PortalContainer.getInstanceIfPresent();
    ServletContext portalContext = container == null ? null : container.getPortalContext();
    return portalContext == null ? controllerContext.getRequest().getServletContext().getContextPath()
                                 : portalContext.getContextPath();
  }

  @Override
  public Map<String, Object> extendParameters(ControllerContext controllerContext, String extensionName) {
    if (!enabled) {
      return null; // NOSONAR
    }
    Map<String, Object> params = new HashMap<>();
    params.put(SAML_LOGIN_ENABLED, true);
    params.put(SAML_LOGIN_URL, getPortalContextPath(controllerContext) + ssoHelper.getSSORedirectURLSuffix());
    params.put("extendedAuthProviderType", "saml");
    return params;
  }

}
