package com.osisoft.pidevclub.piwebapi.auth;

public class KerberosHandler {
    private String host;
    private String service;
    private String ticket;

    public String getHost() {
        return host;
    }
    public KerberosHandler setHost(String host) {
        this.host = host;
        return this;
    }

    public String getService() {
        return service;
    }
    public KerberosHandler setService(String service) {
        this.service = service;
        return this;
    }

    public String getTicket() {
        return ticket;
    }
    public KerberosHandler setTicket(String ticket) {
        this.ticket = ticket;
        return this;
    }
}
