package sh.hyperme.startup;

import jakarta.ws.rs.core.Response;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.Locale;
import java.util.Set;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.TotpBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.theme.Theme;

/** Brand enrollment from the product origin registered on the OIDC client. */
final class TenantOtpLoginForms extends FreeMarkerLoginFormsProvider {
    TenantOtpLoginForms(KeycloakSession session) {
        super(session);
    }

    static String productLabel(String clientId, String callback, Set<String> redirectUris) {
        if (clientId == null || callback == null || redirectUris == null || !redirectUris.contains(callback)) {
            return null;
        }
        try {
            URI uri = URI.create(callback);
            String host = uri.getHost();
            if (!"https".equals(uri.getScheme()) || host == null
                    || !host.equals(uri.getRawAuthority()) || uri.getRawFragment() != null) {
                return null;
            }
            return switch (clientId) {
                case "s3rch-web" -> switch (host) {
                    case "s3r.ch", "www.s3r.ch" -> "s3r.ch";
                    case "test.s3r.ch" -> "test.s3r.ch";
                    default -> null;
                };
                case "controlplane-frontend" -> switch (host) {
                    case "hyperme.sh", "www.hyperme.sh", "portal.hyperme.sh" -> "hyperme.sh";
                    case "test.hyperme.sh", "portal.test.hyperme.sh" -> "test.hyperme.sh";
                    default -> null;
                };
                default -> null;
            };
        } catch (IllegalArgumentException error) {
            return null;
        }
    }

    static RealmModel labelledRealm(RealmModel original, String label) {
        return (RealmModel) Proxy.newProxyInstance(RealmModel.class.getClassLoader(),
            new Class<?>[] {RealmModel.class}, (proxy, method, args) -> {
                if (method.getName().equals("getDisplayName")) {
                    return label;
                }
                try {
                    return method.invoke(original, args);
                } catch (InvocationTargetException error) {
                    throw error.getCause();
                }
            });
    }

    @Override
    protected Response processTemplate(Theme theme, String templateName, Locale locale) {
        if ("login-config-totp.ftl".equals(templateName) && authenticationSession != null
                && realm != null && user != null && authenticationSession.getClient() != null
                && authenticationSession.getAuthenticatedUser() != null
                && user.getId().equals(authenticationSession.getAuthenticatedUser().getId())
                && attributes.get("totp") instanceof TotpBean totp) {
            var client = authenticationSession.getClient();
            String label = productLabel(client.getClientId(), authenticationSession.getRedirectUri(),
                client.getRedirectUris());
            if (label != null) {
                var uri = uriInfo.getBaseUriBuilder().path(uriInfo.getPath())
                    .replaceQuery(uriInfo.getRequestUri().getQuery());
                attributes.put("totp", new TotpBean(session, labelledRealm(realm, label), user,
                    uri, totp.getTotpSecret()));
            }
        }
        return super.processTemplate(theme, templateName, locale);
    }
}
