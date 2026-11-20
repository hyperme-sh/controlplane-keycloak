package sh.hyperme.startup;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;

/** Opt-in login renderer for tenant-labelled authenticator enrollment. */
public final class TenantOtpLoginFormsFactory extends FreeMarkerLoginFormsProviderFactory {
    @Override
    public String getId() {
        return "tenant-otp-freemarker";
    }

    @Override
    public LoginFormsProvider create(KeycloakSession session) {
        return new TenantOtpLoginForms(session);
    }
}
