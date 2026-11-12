package sh.hyperme.startup;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public final class StartupEntraFactory extends OIDCIdentityProviderFactory {
    @Override public String getId() { return "startup-entra"; }
    @Override public String getName() { return "Microsoft Entra with configured startup binding"; }
    @Override public StartupEntraProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new StartupEntraProvider(session,new OIDCIdentityProviderConfig(model));
    }
}
