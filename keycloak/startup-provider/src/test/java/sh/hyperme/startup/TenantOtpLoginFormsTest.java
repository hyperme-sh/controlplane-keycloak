package sh.hyperme.startup;

import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import static org.junit.jupiter.api.Assertions.*;

final class TenantOtpLoginFormsTest {
    @Test
    void installingTheStartupArtifactDoesNotSelectTheRenderer() {
        TenantOtpLoginFormsFactory renderer = new TenantOtpLoginFormsFactory();
        for (boolean optIn : new boolean[] {false, true}) {
            Config.Scope config = (Config.Scope) Proxy.newProxyInstance(Config.Scope.class.getClassLoader(),
                new Class<?>[] {Config.Scope.class}, (proxy, method, args) -> {
                    assertEquals("getBoolean", method.getName());
                    assertArrayEquals(new Object[] {"tenant-labels", false}, args);
                    return optIn;
                });
            assertEquals(optIn, renderer.isSupported(config));
        }
        assertTrue(renderer.order() > 0);
    }

    @Test
    void productLabelUsesTheRegisteredCallbackAndClientAcrossAllFourEnvironments() {
        assertProductLabel("s3rch-web", "https://test.s3r.ch/api/identity/oauth/callback", "test.s3r.ch");
        assertProductLabel("s3rch-web", "https://s3r.ch/api/identity/oauth/callback", "s3r.ch");
        assertProductLabel("s3rch-web", "https://www.s3r.ch/api/identity/oauth/callback", "s3r.ch");
        assertProductLabel("controlplane-frontend", "https://portal.test.hyperme.sh/api/auth/callback/keycloak",
            "test.hyperme.sh");
        assertProductLabel("controlplane-frontend", "https://portal.hyperme.sh/api/auth/callback/keycloak",
            "hyperme.sh");

        String callback = "https://test.s3r.ch/api/identity/oauth/callback";
        assertNull(TenantOtpLoginForms.productLabel("controlplane-frontend", callback, Set.of(callback)));
        assertNull(TenantOtpLoginForms.productLabel("s3rch-web", callback, Set.of("https://test.s3r.ch/*")));
        assertProductLabel("s3rch-web", "https://test.s3r.ch.evil.invalid/api/identity/oauth/callback", null);
        assertProductLabel("s3rch-web", "https://test.hyperme.sh@test.s3r.ch/api/identity/oauth/callback", null);
        assertProductLabel("s3rch-web", "http://test.s3r.ch/api/identity/oauth/callback", null);
        assertProductLabel("s3rch-web", "https://test.s3r.ch:8443/api/identity/oauth/callback", null);
        assertNull(TenantOtpLoginForms.productLabel("s3rch-web", null, Set.of(callback)));
    }

    private static void assertProductLabel(String clientId, String callback, String expected) {
        assertEquals(expected, TenantOtpLoginForms.productLabel(clientId, callback, Set.of(callback)));
    }

    @Test
    void upstreamOtpPolicyChangesOnlyTheLabelAndIssuerForTheProduct() {
        RealmModel original = (RealmModel) Proxy.newProxyInstance(RealmModel.class.getClassLoader(),
            new Class<?>[] {RealmModel.class}, (proxy, method, args) -> switch (method.getName()) {
                case "getDisplayName" -> null;
                case "getName" -> "controlplane";
                case "getOTPPolicy" -> OTPPolicy.DEFAULT_POLICY;
                default -> throw new AssertionError(method.getName());
            });
        UserModel user = (UserModel) Proxy.newProxyInstance(UserModel.class.getClassLoader(),
            new Class<?>[] {UserModel.class}, (proxy, method, args) -> {
                assertEquals("getUsername", method.getName());
                return "member";
            });

        RealmModel branded = TenantOtpLoginForms.labelledRealm(original, "test.s3r.ch");
        RealmModel other = TenantOtpLoginForms.labelledRealm(original, "test.hyperme.sh");
        assertEquals("controlplane", branded.getName());
        assertSame(original.getOTPPolicy(), branded.getOTPPolicy());

        String synthetic = "synthetic-unit-test-secret";
        URI before = URI.create(original.getOTPPolicy().getKeyURI(original, user, synthetic));
        URI after = URI.create(branded.getOTPPolicy().getKeyURI(branded, user, synthetic));
        URI otherTenant = URI.create(other.getOTPPolicy().getKeyURI(other, user, synthetic));
        assertEquals("/controlplane:member", before.getPath());
        assertEquals("/test.s3r.ch:member", after.getPath());
        assertEquals("/test.hyperme.sh:member", otherTenant.getPath());
        assertEquals(before.getRawQuery().replace("issuer=controlplane", "issuer=test.s3r.ch"),
            after.getRawQuery());
        assertNull(original.getDisplayName());
    }
}
