package sh.hyperme.startup;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import static org.junit.jupiter.api.Assertions.*;

final class TenantOtpLoginFormsTest {
    @Test
    void activatesOnlyWithARegularMarkerFile(@TempDir Path directory) throws IOException {
        Path marker = directory.resolve("startup-otp-labels.enabled");
        assertFalse(TenantOtpLoginFormsFactory.activationMarkerPresent(marker));
        Files.createFile(marker);
        assertTrue(TenantOtpLoginFormsFactory.activationMarkerPresent(marker));
        assertFalse(TenantOtpLoginFormsFactory.activationMarkerPresent(directory));
        Path link = Files.createSymbolicLink(directory.resolve("linked-marker"), marker);
        assertFalse(TenantOtpLoginFormsFactory.activationMarkerPresent(link));
    }

    @Test
    void installingTheStartupArtifactDoesNotSelectTheRenderer() {
        TenantOtpLoginFormsFactory renderer = new TenantOtpLoginFormsFactory();
        assertFalse(TenantOtpLoginFormsFactory.labelsEnabled(null));
        assertFalse(TenantOtpLoginFormsFactory.labelsEnabled("false"));
        assertTrue(TenantOtpLoginFormsFactory.labelsEnabled("true"));
        assertTrue(renderer.order() > 0);
    }

    @Test
    void productLabelUsesTheMappingOnTheCurrentClient() {
        String callback = "https://portal.test.hyperme.sh/api/auth/callback/keycloak";
        Set<String> redirects = Set.of(callback);
        String key = "startup.otp.label.portal.test.hyperme.sh";
        assertEquals("test.hyperme.sh",
            TenantOtpLoginForms.productLabel(callback, redirects, Map.of(key, "test.hyperme.sh")));
        assertEquals("Tenant A",
            TenantOtpLoginForms.productLabel(callback, redirects, Map.of(key, "Tenant A")));
        assertNull(TenantOtpLoginForms.productLabel(callback, redirects, Map.of()));
        assertNull(TenantOtpLoginForms.productLabel(callback, redirects, Map.of(key, "other:account")));
    }

    @Test
    void productLabelRequiresAnExactRegisteredHttpsRedirect() {
        String callback = "https://test.s3r.ch/api/identity/oauth/callback";
        Map<String, String> mapping = Map.of("startup.otp.label.test.s3r.ch", "test.s3r.ch");
        assertEquals("test.s3r.ch", TenantOtpLoginForms.productLabel(callback, Set.of(callback), mapping));
        assertNull(TenantOtpLoginForms.productLabel(callback, Set.of("https://test.s3r.ch/*"), mapping));
        assertNull(TenantOtpLoginForms.productLabel(null, Set.of(callback), mapping));
        for (String invalid : Set.of(
                "https://test.s3r.ch/*",
                "https://test.s3r.ch.evil.invalid/api/identity/oauth/callback",
                "https://test.hyperme.sh@test.s3r.ch/api/identity/oauth/callback",
                "http://test.s3r.ch/api/identity/oauth/callback",
                "https://test.s3r.ch:8443/api/identity/oauth/callback",
                callback + "#fragment")) {
            assertNull(TenantOtpLoginForms.productLabel(invalid, Set.of(invalid), mapping), invalid);
        }
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
