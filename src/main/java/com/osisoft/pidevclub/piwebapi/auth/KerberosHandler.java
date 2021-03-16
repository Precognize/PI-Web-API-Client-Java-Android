package com.osisoft.pidevclub.piwebapi.auth;

public class KerberosHandler {
    private String host;
    private Boolean refreshKrb5Config;
    private Boolean doNotPrompt;
    private String keyTabFilePath;
    private Boolean debug;
    private String ticketCacheFilePath;
    private Boolean renewTGT;
    private String principal;

    private Boolean requestMutualAuth;
    private Boolean requestConf;
    private Boolean requestInteg;
    private Boolean requestCredDeleg;

    public String getHost() {
        return host;
    }
    public KerberosHandler setHost(String host) {
        this.host = host;
        return this;
    }

    public Boolean getRefreshKrb5Config() {
        return refreshKrb5Config;
    }
    public KerberosHandler setRefreshKrb5Config(Boolean refreshKrb5Config) {
        this.refreshKrb5Config = refreshKrb5Config;
        return this;
    }

    public Boolean getDoNotPrompt() {
        return doNotPrompt;
    }
    public KerberosHandler setDoNotPrompt(Boolean doNotPrompt) {
        this.doNotPrompt = doNotPrompt;
        return this;
    }

    public String getKeyTabFilePath() {
        return keyTabFilePath;
    }
    public KerberosHandler setKeyTabFilePath(String keyTabFilePath) {
        this.keyTabFilePath = keyTabFilePath;
        return this;
    }

    public Boolean getDebug() {
        return debug;
    }
    public KerberosHandler setDebug(Boolean debug) {
        this.debug = debug;
        return this;
    }

    public String getTicketCacheFilePath() {
        return ticketCacheFilePath;
    }
    public KerberosHandler setTicketCacheFilePath(String ticketCacheFilePath) {
        this.ticketCacheFilePath = ticketCacheFilePath;
        return this;
    }

    public Boolean getRenewTGT() {
        return renewTGT;
    }
    public KerberosHandler setRenewTGT(Boolean renewTGT) {
        this.renewTGT = renewTGT;
        return this;
    }

    public String getPrincipal() {
        return principal;
    }
    public KerberosHandler setPrincipal(String principal) {
        this.principal = principal;
        return this;
    }

    public Boolean getRequestMutualAuth() {
        return requestMutualAuth;
    }
    public KerberosHandler setRequestMutualAuth(Boolean requestMutualAuth) {
        this.requestMutualAuth = requestMutualAuth;
        return this;
    }

    public Boolean getRequestConf() {
        return requestConf;
    }
    public KerberosHandler setRequestConf(Boolean requestConf) {
        this.requestConf = requestConf;
        return this;
    }

    public Boolean getRequestInteg() {
        return requestInteg;
    }
    public KerberosHandler setRequestInteg(Boolean requestInteg) {
        this.requestInteg = requestInteg;
        return this;
    }

    public Boolean getRequestCredDeleg() {
        return requestCredDeleg;
    }
    public KerberosHandler setRequestCredDeleg(Boolean requestCredDeleg) {
        this.requestCredDeleg = requestCredDeleg;
        return this;
    }
}
