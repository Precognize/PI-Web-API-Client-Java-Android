package com.osisoft.pidevclub.piwebapi.auth;

import com.google.common.collect.ImmutableMap;
import com.osisoft.pidevclub.piwebapi.ApiClient;
import com.osisoft.pidevclub.piwebapi.Pair;
import com.sun.security.auth.module.Krb5LoginModule;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static com.google.common.base.Throwables.throwIfInstanceOf;
import static com.google.common.base.Throwables.throwIfUnchecked;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
import static org.ietf.jgss.GSSContext.DEFAULT_LIFETIME;
import static org.ietf.jgss.GSSCredential.INDEFINITE_LIFETIME;
import static org.ietf.jgss.GSSCredential.INITIATE_ONLY;
import static org.ietf.jgss.GSSName.NT_HOSTBASED_SERVICE;
import static org.ietf.jgss.GSSName.NT_USER_NAME;

public class KerberosCachedTicketAuth extends KerberosAuth {
    private static final Logger logger = LoggerFactory.getLogger(KerberosCachedTicketAuth.class);

    public KerberosCachedTicketAuth(KerberosHandler handler) {
        super(handler);
    }

    @Override
    public void applyToParams(List<Pair> queryParams, Map<String, String> headerParams) {
        logger.debug("applyToParams");

        String principal = makeServicePrincipal(handler.getService(), handler.getHost());
        logger.debug("principal: " + principal);

        byte[] token = generateToken(principal);

        String credential = format("%s %s", NEGOTIATE, Base64.getEncoder().encodeToString(token));
        headerParams.put(AUTHORIZATION, credential);

        logger.debug("AUTHORIZATION: " + credential);
    }


    private static String makeServicePrincipal(String serviceName, String hostName) {
        return format("%s@%s", serviceName, hostName.toLowerCase(Locale.US));
    }

    private byte[] generateToken(String servicePrincipal) {
        GSSContext context = null;
        try {

            logger.debug("open session");
            Session session = createSession(servicePrincipal, new File(handler.getTicket()));

            logger.debug("build context");
            context = doAs(session.getLoginContext().getSubject(), () -> {

                logger.debug("GSS_MANAGER.createContext");
                GSSContext result = GSS_MANAGER.createContext(
                        GSS_MANAGER.createName(servicePrincipal, NT_HOSTBASED_SERVICE),
                        SPNEGO_OID,
                        session.getClientCredential(),
                        INDEFINITE_LIFETIME);

                result.requestMutualAuth(true);
                result.requestConf(true);
                result.requestInteg(true);
                result.requestCredDeleg(false);

                return result;
            });

            logger.debug("generate token");
            byte[] token = context.initSecContext(new byte[0], 0, 0);
            if (token == null) {
                throw new LoginException("No token generated from GSS context");
            }
            return token;
        } catch (GSSException | LoginException e) {
            logger.error(e.getMessage(), e);
            throw new RuntimeException(format("Kerberos error for [%s]: %s", servicePrincipal, e.getMessage()), e);
        } finally {
            try {
                if (context != null) {
                    context.dispose();
                }
            } catch (GSSException ignored) {
                logger.warn(ignored.getMessage(), ignored);
            }
        }
    }

    private Session createSession(String servicePrincipal, File credentialCache) throws LoginException, GSSException {
        // TODO: (ls) -> do we need to call logout() on the LoginContext?
        LoginContext loginContext = new LoginContext("", null, null, new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                ImmutableMap.Builder<String, String> options = ImmutableMap.builder();

                options.put("refreshKrb5Config", "true");
                options.put("doNotPrompt", "true");
                options.put("useKeyTab", "true");
                options.put("debug", "true");

/*
                keytab.ifPresent(file -> options.put("keyTab", file.getAbsolutePath()));
*/

                options.put("ticketCache", credentialCache.getAbsolutePath());
                options.put("useTicketCache", "true");
                options.put("renewTGT", "true");
                options.put("principal", servicePrincipal);

                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(Krb5LoginModule.class.getName(), REQUIRED, options.build())
                };
            }
        });

        logger.debug("loginContext.login ");

        loginContext.login();
        Subject subject = loginContext.getSubject();

        Principal clientPrincipal = subject.getPrincipals().iterator().next();
        GSSCredential clientCredential = doAs(subject, () -> GSS_MANAGER.createCredential(
                GSS_MANAGER.createName(clientPrincipal.getName(), NT_USER_NAME),
                DEFAULT_LIFETIME,
                KERBEROS_OID,
                INITIATE_ONLY));

        return new Session(loginContext, clientCredential);
    }

    private static <T> T doAs(Subject subject, GssSupplier<T> action) throws GSSException {
        try {
            return Subject.doAs(subject, (PrivilegedExceptionAction<T>) action::get);
        } catch (PrivilegedActionException e) {
            Throwable t = e.getCause();
            throwIfInstanceOf(t, GSSException.class);
            throwIfUnchecked(t);

            throw new RuntimeException(t);
        }
    }


    private interface GssSupplier<T> {
        T get() throws GSSException;
    }


    private static class Session {
        private final LoginContext loginContext;
        private final GSSCredential clientCredential;

        public Session(LoginContext loginContext, GSSCredential clientCredential) {
            requireNonNull(loginContext, "loginContext is null");
            requireNonNull(clientCredential, "gssCredential is null");

            this.loginContext = loginContext;
            this.clientCredential = clientCredential;
        }

        public LoginContext getLoginContext() {
            return loginContext;
        }

        public GSSCredential getClientCredential() {
            return clientCredential;
        }

        public boolean needsRefresh() throws GSSException {
            return clientCredential.getRemainingLifetime() < MAX_CREDENTIAL_LIFETIME_SECONDS;
        }
    }
}
