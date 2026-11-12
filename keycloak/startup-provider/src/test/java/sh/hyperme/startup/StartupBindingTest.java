package sh.hyperme.startup;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class StartupBindingTest {
    final Map<String,String> config=Map.of("startupTenant","tenant","startupAccount","account","startupIssuer","https://issuer.invalid","startupSubject","reserved","startupEmail","label@example.invalid");
    @Test void exactTuplePreservesChosenLink() { assertEquals("reserved",StartupBinding.select(config,"https://issuer.invalid",Map.of("tid","tenant","oid","account","ver","2.0"),"reserved","changed-label@example.invalid")); }
    @Test void sameEmailNeverSelectsIdentity() { assertThrows(IllegalArgumentException.class,()->StartupBinding.select(config,"https://issuer.invalid",Map.of("tid","tenant","oid","attacker"),"attacker","label@example.invalid")); }
    @Test void wrongIssuerCannotUseReservedSubject() { assertThrows(IllegalArgumentException.class,()->StartupBinding.select(config,"https://wrong.invalid",Map.of("tid","tenant","oid","account"),"reserved",null)); }
    @Test void unrelatedAccountsCannotUseDedicatedBroker() { assertThrows(IllegalArgumentException.class,()->StartupBinding.select(config,"https://issuer.invalid",Map.of("tid","tenant","oid","other"),"other","other@example.invalid")); }
    @Test void changedRawSubjectCannotSelectConfiguredAccount() { assertThrows(IllegalArgumentException.class,()->StartupBinding.select(config,"https://issuer.invalid",Map.of("tid","tenant","oid","account","ver","2.0"),"reserved-other","label@example.invalid")); }
    @Test void incompleteConfigurationFailsClosed() { assertThrows(IllegalArgumentException.class,()->StartupBinding.select(Map.of(),"https://issuer.invalid",Map.of(),"anything",null)); }
}
