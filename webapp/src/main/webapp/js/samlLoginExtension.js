/*
 * Adds a "Sign in with SAML" button to the portal login page.
 * The button is displayed only when the add-on exposes the login parameter
 * samlLoginEnabled (gatein.sso.saml.login.page.enabled=true).
 *
 * An AMD module that returns an object: the login form calls init() on every
 * module named ...LoginExtension.
 */
// 'extensionRegistry' is the alias of the module declared in <depends> (gatein-resources.xml)
define(['extensionRegistry'], function(extensionRegistry) {
  let loginUrl = null;

  const buildUrl = () => {
    const initialURI = new URLSearchParams(window.location.search).get('initialURI');
    // The query string is always present: the login component appends
    // parameters to the link with '&'
    return initialURI
      ? `${loginUrl}?initialURI=${encodeURIComponent(initialURI)}`
      : `${loginUrl}?saml=true`;
  };

  extensionRegistry.registerExtension('LoginProvider', 'login-provider', {
    id: 'saml',
    key: 'saml',
    rank: 5,
    image: '/saml2-addon/images/saml.svg',
    isEnabled: params => {
      if (params?.samlLoginEnabled && params?.samlLoginUrl) {
        loginUrl = params.samlLoginUrl;
        return true;
      }
      return false;
    },
    get url() {
      return loginUrl && buildUrl();
    },
  });

  return {
    init: () => {},
  };
});
