package com.osisoft.pidevclub.piwebapi.auth;

import com.osisoft.pidevclub.piwebapi.Pair;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

import java.util.List;
import java.util.Map;

public class KerberosAuth implements Authentication {
    protected static final Oid SPNEGO_OID = createOid("1.3.6.1.5.5.2");
    protected static final Oid KERBEROS_OID = createOid("1.2.840.113554.1.2.2");

    protected static final GSSManager GSS_MANAGER = GSSManager.getInstance();
    protected static final String NEGOTIATE = "Negotiate";

    protected static final Integer MAX_CREDENTIAL_LIFETIME_SECONDS = 300;

    protected KerberosHandler handler;

    public KerberosAuth(KerberosHandler handler) {
        //TODO: (ls) -> handler assertions
        this.handler = handler;
    }

    @Override
    public void applyToParams(List<Pair> queryParams, Map<String, String> headerParams) {
        throw new RuntimeException("not implemented");
    }

    private static Oid createOid(String value) {
        try {
            return new Oid(value);
        } catch (GSSException e) {
            throw new AssertionError(e);
        }
    }
}
