package org.exoplatform.addons.saml.extensions;

import java.io.Serializable;

/**
 * The page a user asked for before the IDP: the request URI and the query
 * string, enough for the redirect of the parent valve (no cookie, header or
 * locale of the request is kept).
 *
 * @param requestURI the request URI, as sent
 * @param decodedRequestURI the request URI, decoded
 * @param queryString the query string, or null
 */
record SamlRelayTarget(String requestURI, String decodedRequestURI, String queryString) implements Serializable {
}
