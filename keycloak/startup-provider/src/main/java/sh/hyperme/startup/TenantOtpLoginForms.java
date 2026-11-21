package sh.hyperme.startup;

import jakarta.ws.rs.core.Response;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.RealmBean;
import org.keycloak.forms.login.freemarker.model.TotpBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.theme.Theme;

/** Brand enrollment from the product origin registered on the OIDC client. */
final class TenantOtpLoginForms extends FreeMarkerLoginFormsProvider {
    TenantOtpLoginForms(KeycloakSession session) {
        super(session);
    }

    static String productLabel(String callback, Set<String> redirectUris, Map<String, String> clientAttributes) {
        if (callback == null || redirectUris == null || !redirectUris.contains(callback) || clientAttributes == null) {
            return null;
        }
        URI uri;
        try {
            uri = URI.create(callback);
        } catch (IllegalArgumentException error) {
            return null;
        }
        String host = uri.getHost();
        if (!"https".equals(uri.getScheme()) || host == null || callback.contains("*")
                || !host.equals(uri.getRawAuthority()) || uri.getRawFragment() != null) {
            return null;
        }
        String label = clientAttributes.get("startup.otp.label." + host.toLowerCase(Locale.ROOT));
        if (label == null || label.isBlank() || label.indexOf(':') >= 0 || label.indexOf('/') >= 0
                || label.codePoints().anyMatch(Character::isISOControl)) {
            return null;
        }
        return label.strip();
    }

    static RealmModel labelledRealm(RealmModel original, String label) {
        return (RealmModel) Proxy.newProxyInstance(RealmModel.class.getClassLoader(),
            new Class<?>[] {RealmModel.class}, (proxy, method, args) -> {
                if (method.getName().equals("getDisplayName")) {
                    return label;
                }
                if (method.getName().equals("getDisplayNameHtml")) {
                    return null;
                }
                try {
                    return method.invoke(original, args);
                } catch (InvocationTargetException error) {
                    throw error.getCause();
                }
            });
    }

    static boolean isOtpTemplate(String template) {
        return "login-config-totp.ftl".equals(template) || "login-otp.ftl".equals(template);
    }

    @Override
    protected Response processTemplate(Theme theme, String templateName, Locale locale) {
        if (isOtpTemplate(templateName) && authenticationSession != null && realm != null
                && authenticationSession.getClient() != null) {
            var client = authenticationSession.getClient();
            String label = productLabel(authenticationSession.getRedirectUri(),
                client.getRedirectUris(), client.getAttributes());
            if (label != null) {
                RealmModel brandedRealm = labelledRealm(realm, label);
                attributes.put("realm", new RealmBean(brandedRealm));
                if (user != null && authenticationSession.getAuthenticatedUser() != null
                        && user.getId().equals(authenticationSession.getAuthenticatedUser().getId())
                        && attributes.get("totp") instanceof TotpBean totp) {
                    var uri = uriInfo.getBaseUriBuilder().path(uriInfo.getPath())
                        .replaceQuery(uriInfo.getRequestUri().getQuery());
                    attributes.put("totp", new TotpBean(session, brandedRealm, user, uri, totp.getTotpSecret()));
                }
            }
        }
        return super.processTemplate(theme, templateName, locale);
    }
}
