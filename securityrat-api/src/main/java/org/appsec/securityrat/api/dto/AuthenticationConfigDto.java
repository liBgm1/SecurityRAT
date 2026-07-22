package org.appsec.securityrat.api.dto;

import lombok.Data;

@Data
public class AuthenticationConfigDto implements Dto {
    public enum Type {
        FORM,
        CAS,
        LDAP,
        OIDC
    }
    
    private Type type;
    private Boolean registration;
    private String casLogout;
    private String oidcClientId;
    private String oidcRegistrationId;
}
