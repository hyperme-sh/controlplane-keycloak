package sh.hyperme.startup;

import org.keycloak.Config;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

/** Opt-in login renderer for tenant-labelled authenticator enrollment. */
public final class TenantOtpLoginFormsFactory extends FreeMarkerLoginFormsProviderFactory
        implements EnvironmentDependentProviderFactory {
    @Override
    public String getId() {
        return "tenant-otp-freemarker";
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return config.getBoolean("tenant-labels", false);
    }

    @Override
    public int order() {
        return 1;
    }

    @Override
    public LoginFormsProvider create(KeycloakSession session) {
        return new TenantOtpLoginForms(session);
    }
}
