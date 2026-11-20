package sh.hyperme.startup;

import jakarta.ws.rs.core.Response;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.Locale;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.TotpBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.theme.Theme;

/** Use the configured tenant display name in the QR code for a bound account. */
final class TenantOtpLoginForms extends FreeMarkerLoginFormsProvider {
    private static final String LABEL_PREFIX = "startup.otp.tenant.";

    TenantOtpLoginForms(KeycloakSession session) {
        super(session);
    }

    static String labelAttribute(String clientId, String subject) {
        if (clientId == null || !clientId.matches("[a-zA-Z0-9_-]{1,128}")
                || subject == null || !subject.matches("[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}")) {
            return null;
        }
        return LABEL_PREFIX + clientId + "." + subject;
    }

    static boolean validLabel(String label) {
        return label != null && !label.isBlank() && label.equals(label.strip())
            && label.length() <= 128 && label.codePoints().noneMatch(cp ->
                cp == ':' || cp == '/' || Character.isISOControl(cp));
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
            String attribute = labelAttribute(authenticationSession.getClient().getClientId(), user.getId());
            String label = attribute == null ? null : realm.getAttribute(attribute);
            if (validLabel(label)) {
                var uri = uriInfo.getBaseUriBuilder().path(uriInfo.getPath())
                    .replaceQuery(uriInfo.getRequestUri().getQuery());
                attributes.put("totp", new TotpBean(session, labelledRealm(realm, label), user,
                    uri, totp.getTotpSecret()));
            }
        }
        return super.processTemplate(theme, templateName, locale);
    }
}
