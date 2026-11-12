package sh.hyperme.startup;

import java.io.IOException;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;

public final class StartupEntraProvider extends OIDCIdentityProvider {
    public StartupEntraProvider(KeycloakSession session, OIDCIdentityProviderConfig config) { super(session,config); }
    @Override protected BrokeredIdentityContext extractIdentity(AccessTokenResponse response, String accessToken, JsonWebToken token) throws IOException {
        BrokeredIdentityContext identity = super.extractIdentity(response,accessToken,token);
        String selected=StartupBinding.select(getConfig().getConfig(),token.getIssuer(),token.getOtherClaims(),identity.getId(),identity.getEmail());
        // The base provider checks ID-token subject equality after extraction.
        // Keep that check intact; rewrite in preprocess only after it succeeds.
        identity.getContextData().put("startupSelectedSubject",selected);
        return identity;
    }
    @Override public void preprocessFederatedIdentity(KeycloakSession session, org.keycloak.models.RealmModel realm, BrokeredIdentityContext context) {
        super.preprocessFederatedIdentity(session,realm,context);
        Object selected=context.getContextData().get("startupSelectedSubject");
        if (!(selected instanceof String) || ((String)selected).isBlank()) throw new IllegalArgumentException("Verified startup broker subject missing");
        context.setId((String)selected);
    }
}
