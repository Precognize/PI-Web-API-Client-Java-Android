package com.osisoft.pidevclub.piwebapi.auth;

import com.google.common.collect.ImmutableMap;
import com.osisoft.pidevclub.piwebapi.Pair;
import com.sun.security.auth.module.Krb5LoginModule;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.ietf.jgss.*;

import javax.annotation.concurrent.GuardedBy;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOError;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static com.google.common.base.Throwables.throwIfInstanceOf;
import static com.google.common.base.Throwables.throwIfUnchecked;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
import static org.ietf.jgss.GSSContext.DEFAULT_LIFETIME;
import static org.ietf.jgss.GSSCredential.INITIATE_ONLY;
import static org.ietf.jgss.GSSName.NT_USER_NAME;

public class KerberosAuth implements Authentication {
    private static final Logger logger = LogManager.getLogger(KerberosAuth.class);

    protected static final Oid KERBEROS_OID = createOid("1.2.840.113554.1.2.2");
    protected static final Oid KERBEROS_PRINCIPAL_OID = createOid("1.2.840.113554.1.2.2.1");

    protected static final GSSManager GSS_MANAGER = GSSManager.getInstance();
    protected static final String NEGOTIATE = "Negotiate";

    protected static final Integer MAX_CREDENTIAL_LIFETIME_SECONDS = 60;

    protected KerberosHandler handler;

    @GuardedBy("this")
    private Session clientSession;

    public KerberosAuth(KerberosHandler handler) {
        //TODO: (ls) -> handler assertions
        this.handler = handler;
    }

    @Override
    public void applyToParams(List<Pair> queryParams, Map<String, String> headerParams) {
        logDebug("applyToParams");

        byte[] token = generateToken();
        logDebug("token " + new String(token));

        String credential = format("%s %s", NEGOTIATE, Base64.getEncoder().encodeToString(token));
        headerParams.put(AUTHORIZATION, credential);

        logDebug(String.join(":", AUTHORIZATION, credential));
    }


    private static String makeServicePrincipal(String hostName) {
        return "HTTP/" + StringUtils.lowerCase(hostName);
    }


    private synchronized Session getSession() throws LoginException, GSSException {
        if ((clientSession == null) || clientSession.needsRefresh()) {
            clientSession = createSession();
        }
        return clientSession;
    }

    private byte[] generateToken() {
        String principal = makeServicePrincipal(handler.getHost());
        logDebug("principal: " + principal);

        GSSContext context = null;
        try {

            logDebug("open session");
            Session session = getSession();

            logDebug("session credential " + session.getClientCredential().getName().toString());
            logDebug("session credential remaining lifetime" + session.getClientCredential().getRemainingLifetime());

            logDebug("build context");
            context = doAs(session.getLoginContext().getSubject(), () -> {

                logDebug("GSS_MANAGER.createContext");

                GSSContext result = GSS_MANAGER.createContext(
                        GSS_MANAGER.createName(principal, KERBEROS_PRINCIPAL_OID),
                        KERBEROS_OID,
                        session.getClientCredential(),
                        DEFAULT_LIFETIME
                );

                result.requestMutualAuth(mapToBoolean(handler, KerberosHandler::getRequestMutualAuth, true));
                result.requestConf(mapToBoolean(handler, KerberosHandler::getRequestConf, true));
                result.requestInteg(mapToBoolean(handler, KerberosHandler::getRequestInteg, true));
                result.requestCredDeleg(mapToBoolean(handler, KerberosHandler::getRequestCredDeleg, false));

                return result;
            });

            logDebug("generate token");
            byte[] token = context.initSecContext(new byte[0], 0, 0);

            if (token == null) {
                throw new LoginException("No token generated from GSS context");
            }

            return token;

        } catch (GSSException | LoginException e) {
            logger.error(e.getMessage(), e);
            throw new RuntimeException(format("Kerberos error for [%s]: %s", principal, e.getMessage()), e);

        } finally {
            try {
                if (context != null) {
                    context.dispose();
                }
            } catch (GSSException ignoredException) {
                logger.warn(ignoredException.getMessage(), ignoredException);
            }
        }
    }

    private String mapToBooleanString(KerberosHandler handler, Function<KerberosHandler, Boolean> mapper, boolean defaultValue){
        return String.valueOf(mapToBoolean(handler,mapper,defaultValue));
    }
    private Boolean mapToBoolean(KerberosHandler handler, Function<KerberosHandler, Boolean> mapper, boolean defaultValue){
        return Optional.ofNullable(handler).map(mapper).orElse(defaultValue);
    }

    private Optional<String> mapToAbsolutePath(KerberosHandler handler, Function<KerberosHandler, String> mapper, Marker marker){
        return Optional.ofNullable(handler)
                .map(mapper)
                .map(path -> {
                    try {
                        return Paths.get(path).toAbsolutePath();
                    } catch (InvalidPathException | IOError | SecurityException exception){
                        logger.error(marker, "path error", exception);
                        return null;
                    }
                })
                .map(Path::toString);
    }

    private Session createSession() throws LoginException, GSSException {
        LoginContext loginContext = new LoginContext("Krb5LoginContext", null, null, new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                ImmutableMap.Builder<String, String> options = ImmutableMap.builder();

                options.put("refreshKrb5Config", mapToBooleanString(handler, KerberosHandler::getRefreshKrb5Config, false));
                options.put("doNotPrompt", mapToBooleanString(handler, KerberosHandler::getDoNotPrompt, true));
                options.put("debug", mapToBooleanString(handler, KerberosHandler::getDebug, false));
                options.put("principal", handler.getPrincipal());

                //TODO: (ls) -> think about this parameters
                //options.put("isInitiator", "false");
                //options.put("storeKey", "true");
                //options.put("useFirstPass", "");
                //options.put("tryFirstPass", "true");
                //options.put("storePass", "");
                //options.put("clearPass", "");

                mapToAbsolutePath(handler,KerberosHandler::getKeyTabFilePath, MarkerManager.getMarker("keyTab"))
                        .ifPresent(path -> {
                            options.put("useKeyTab", "true");
                            options.put("keyTab", path);
                        });

                mapToAbsolutePath(handler,KerberosHandler::getTicketCacheFilePath, MarkerManager.getMarker("ticketCache"))
                        .ifPresent(path -> {
                            options.put("useTicketCache", "true");
                            options.put("renewTGT", mapToBooleanString(handler, KerberosHandler::getRenewTGT, true));
                            options.put("ticketCache", path);
                        });


                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(Krb5LoginModule.class.getName(), REQUIRED, options.build())
                };
            }
        });

        logDebug("loginContext.login ");

        loginContext.login();
        Subject subject = loginContext.getSubject();

        logDebug(String.join(":", "loginContext.subject", subject.toString()));

        Principal clientPrincipal = subject.getPrincipals().iterator().next();

        logDebug("clientPrincipal.getName" + clientPrincipal.getName());

        GSSCredential clientCredential = doAs(
                subject,
                () -> GSS_MANAGER.createCredential(
                        GSS_MANAGER.createName(clientPrincipal.getName(), NT_USER_NAME),
                        DEFAULT_LIFETIME,
                        KERBEROS_OID,
                        INITIATE_ONLY
                )
        );
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

    private void logDebug(String message){
        //TODO: (ls) -> use supplier
        if (logger.isDebugEnabled())
            logger.debug(message);
    }


    private static Oid createOid(String value) {
        try {
            return new Oid(value);
        } catch (GSSException e) {
            throw new AssertionError(e);
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
