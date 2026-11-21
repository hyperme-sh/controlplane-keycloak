package sh.hyperme.startup;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import org.keycloak.Config;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

/** Opt-in login renderer for tenant-labelled authenticator enrollment. */
public final class TenantOtpLoginFormsFactory extends FreeMarkerLoginFormsProviderFactory
        implements EnvironmentDependentProviderFactory {
    private static final Path OPT_IN = Path.of("/opt/keycloak/conf/startup-otp-labels.enabled");
    @Override
    public String getId() {
        return "tenant-otp-freemarker";
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return labelsEnabled(System.getenv("KEYCLOAK_OTP_LABELS_ENABLED"))
                || Files.isRegularFile(OPT_IN, LinkOption.NOFOLLOW_LINKS);
    }

    static boolean labelsEnabled(String setting) {
        return "true".equals(setting);
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
