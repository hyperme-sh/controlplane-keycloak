package sh.hyperme.startup;

import java.lang.reflect.Proxy;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import static org.junit.jupiter.api.Assertions.*;

final class TenantOtpLoginFormsTest {
    @Test
    void onlyAnExactClientAndSubjectCanNameALabel() {
        String subject = "00000000-0000-4000-8000-000000000001";
        assertEquals("startup.otp.tenant.s3rch-web." + subject,
            TenantOtpLoginForms.labelAttribute("s3rch-web", subject));
        assertNotEquals(TenantOtpLoginForms.labelAttribute("s3rch-web", subject),
            TenantOtpLoginForms.labelAttribute("controlplane-frontend", subject));
        assertNull(TenantOtpLoginForms.labelAttribute("s3rch-web.other", subject));
        assertNull(TenantOtpLoginForms.labelAttribute("s3rch-web", "by-email@example.invalid"));
        assertNull(TenantOtpLoginForms.labelAttribute(null, subject));
        assertTrue(TenantOtpLoginForms.validLabel("hyperme.sh TEST"));
        assertTrue(TenantOtpLoginForms.validLabel("s3r.ch TEST"));
        assertFalse(TenantOtpLoginForms.validLabel("hyperme.sh:TEST"));
        assertFalse(TenantOtpLoginForms.validLabel("s3r.ch / TEST"));
        assertFalse(TenantOtpLoginForms.validLabel("s3r.ch\nTEST"));
        assertFalse(TenantOtpLoginForms.validLabel(null));
    }

    @Test
    void upstreamOtpPolicyChangesOnlyTheLabelAndIssuerForTheBoundTenant() {
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

        RealmModel branded = TenantOtpLoginForms.labelledRealm(original, "hyperme.sh TEST");
        RealmModel other = TenantOtpLoginForms.labelledRealm(original, "s3r.ch TEST");
        assertEquals("controlplane", branded.getName());
        assertSame(original.getOTPPolicy(), branded.getOTPPolicy());

        String synthetic = "synthetic-unit-test-secret";
        URI before = URI.create(original.getOTPPolicy().getKeyURI(original, user, synthetic));
        URI after = URI.create(branded.getOTPPolicy().getKeyURI(branded, user, synthetic));
        URI otherTenant = URI.create(other.getOTPPolicy().getKeyURI(other, user, synthetic));
        assertEquals("/controlplane:member", before.getPath());
        assertEquals("/hyperme.sh TEST:member", after.getPath());
        assertEquals("/s3r.ch TEST:member", otherTenant.getPath());
        assertEquals(before.getRawQuery().replace("issuer=controlplane", "issuer=hyperme.sh%20TEST"),
            after.getRawQuery());
        assertNull(original.getDisplayName());
    }
}
