package sh.hyperme.startup;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import java.util.Objects;
import org.keycloak.Config;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Reports whether the single, prelinked synthetic TEST operator retains its declared binding. */
public final class StartupObserverFactory implements RealmResourceProviderFactory {
    private static final String CLIENT = "startup-nightly-reader";
    private static final String ISSUER = "https://auth.test.hyperme.sh/realms/controlplane";
    private static final String BROKER = "startup-nightly";
    private static final Map<String, String> PROVIDER_CONFIG = Map.of(
            "issuer", "https://auth.test.hyperme.sh/realms/startup-nightly",
            "validateSignature", "true", "useJwksUrl", "true",
            "pkceEnabled", "true", "pkceMethod", "S256", "clientId", "startup-nightly-broker");

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new RealmResourceProvider() {
            @Override public Object getResource() { return new Resource(session); }
            @Override public void close() {}
        };
    }

    @Override public String getId() { return "startup-nightly-observation"; }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}

    @jakarta.ws.rs.ext.Provider
    public static final class Resource {
        private final KeycloakSession session;

        Resource(KeycloakSession session) {
            this.session = session;
        }

        @GET
        @Produces(MediaType.APPLICATION_JSON)
        public Response observe() {
            RealmModel realm = session.getContext().getRealm();
            if (!"controlplane".equals(realm.getName())) {
                return Response.status(404).build();
            }
            ClientModel reader = realm.getClientByClientId(CLIENT);
            if (reader == null || !reader.isEnabled() || reader.isPublicClient()
                    || !reader.isServiceAccountsEnabled() || reader.isStandardFlowEnabled()
                    || reader.isDirectAccessGrantsEnabled() || reader.isFullScopeAllowed()) {
                return Response.status(404).build();
            }
            var auth = new AppAuthManager.BearerTokenAuthenticator(session).setAudience(CLIENT).authenticate();
            UserModel serviceAccount = session.users().getServiceAccount(reader);
            if (auth == null || serviceAccount == null
                    || !ISSUER.equals(auth.token().getIssuer())
                    || !CLIENT.equals(auth.token().getIssuedFor())
                    || !serviceAccount.getId().equals(auth.token().getSubject())) {
                return Response.status(401).build();
            }
            String subject = reader.getAttribute("startup-nightly.operator-subject");
            String upstream = reader.getAttribute("startup-nightly.operator-upstream-subject");
            if (subject == null || upstream == null || !providerMatches(realm)) {
                return conflict();
            }
            UserModel operator = session.users().getUserById(realm, subject);
            if (operator == null || !operator.isEnabled()
                    || !"brokered-startup-nightly-operator".equals(operator.getUsername())) {
                return conflict();
            }
            var links = session.users().getFederatedIdentitiesStream(realm, operator).limit(2).toList();
            if (links.size() != 1 || !BROKER.equals(links.getFirst().getIdentityProvider())
                    || !upstream.equals(links.getFirst().getUserId())
                    || !"startup-nightly-operator".equals(links.getFirst().getUserName())) {
                return conflict();
            }
            ClientModel management = realm.getClientByClientId("realm-management");
            if (management == null || operator.getGroupsStream().findAny().isPresent()
                    || operator.getRoleMappingsStream().anyMatch(role ->
                            role.isClientRole() || !"default-roles-controlplane".equals(role.getName()))
                    || RoleUtils.getDeepUserRoleMappings(operator).stream().anyMatch(role ->
                            role.isClientRole() && management.getId().equals(role.getContainerId()))) {
                return conflict();
            }
            return Response.ok(Map.of("schema_version", 1, "realm", realm.getName(),
                    "broker_subject", subject, "upstream_subject", upstream, "keycloak_admin", false)).build();
        }

        private boolean providerMatches(RealmModel realm) {
            IdentityProviderModel provider = session.identityProviders().getByAlias(BROKER);
            return provider != null && "oidc".equals(provider.getProviderId())
                    && Boolean.TRUE.equals(provider.isEnabled()) && Boolean.TRUE.equals(provider.isHideOnLogin())
                    && Boolean.FALSE.equals(provider.isTrustEmail()) && Boolean.FALSE.equals(provider.isStoreToken())
                    && flowMatches(realm, provider.getFirstBrokerLoginFlowId(), "deny-unlinked-broker-login")
                    && flowMatches(realm, provider.getPostBrokerLoginFlowId(), "test-startup-github-mfa")
                    && PROVIDER_CONFIG.entrySet().stream().allMatch(entry ->
                            Objects.equals(entry.getValue(), provider.getConfig().get(entry.getKey())));
        }

        private boolean flowMatches(RealmModel realm, String id, String alias) {
            AuthenticationFlowModel flow = id == null ? null : realm.getAuthenticationFlowById(id);
            return flow != null && alias.equals(flow.getAlias());
        }

        private Response conflict() {
            return Response.status(409).entity(Map.of("error", "startup-nightly-operator-differs")).build();
        }
    }
}
