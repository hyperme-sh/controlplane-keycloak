package sh.hyperme.startup;

import java.util.Map;
import java.util.Objects;

/** Operates only on signature-verified OIDC token claims. Email can only deny. */
public final class StartupBinding {
    private StartupBinding() {}
    public static String select(Map<String,String> config, String issuer, Map<String,Object> claims,
                                String upstreamSubject, String email) {
        for (String key : new String[]{"startupTenant", "startupAccount", "startupIssuer", "startupSubject", "startupEmail"}) {
            if (config.get(key) == null || config.get(key).isBlank()) throw new IllegalArgumentException("Startup broker configuration incomplete");
        }
        boolean matches = Objects.equals(issuer,config.get("startupIssuer"))
            && Objects.equals(claims.get("tid"),config.get("startupTenant"))
            && Objects.equals(claims.get("oid"),config.get("startupAccount"))
            && Objects.equals(claims.get("ver"),"2.0")
            && Objects.equals(upstreamSubject,config.get("startupSubject"));
        if (matches) return config.get("startupSubject");
        throw new IllegalArgumentException("Configured startup identity conflicts with broker account");
    }
}
