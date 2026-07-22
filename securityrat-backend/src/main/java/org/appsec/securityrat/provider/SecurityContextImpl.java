package org.appsec.securityrat.provider;

import org.appsec.securityrat.api.dto.AuthorityDto;
import org.appsec.securityrat.api.dto.user.InternalUserDto;
import org.appsec.securityrat.api.provider.SecurityContext;
import org.appsec.securityrat.api.provider.advanced.UserManager;
import org.appsec.securityrat.provider.mapper.OidcAuthorityMapper;
import org.appsec.securityrat.provider.mapper.LdapAuthorityMapper;
import org.appsec.securityrat.security.AuthoritiesConstants;
import org.appsec.securityrat.security.SecurityUtils;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.springframework.security.authentication.Pac4jAuthentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.ldap.userdetails.LdapAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.stereotype.Service;

import javax.inject.Inject;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class SecurityContextImpl implements SecurityContext {
    @Inject
    private UserManager userManager;

    @Inject
    private LdapAuthorityMapper ldapAuthorityMapper;

    @Inject
    private OidcAuthorityMapper oidcAuthorityMapper;

    private static final Logger log = LoggerFactory.getLogger(SecurityContextImpl.class);

    @Override
    public InternalUserDto getCurrentUser() {
        if (SecurityUtils.isCasAuthentication()) {
            return getCurrentCasUser();
        } else if(SecurityUtils.isLdapAuthentication()) {
            return getCurrentLdapUser();
        } else if (SecurityUtils.isOidcAuthentication()) {
            return getCurrentOidcUser();
        } else {
            return SecurityUtils.getCurrentUserLogin()
                .map(this.userManager::findByLogin)
                .orElse(null);
        }
    }

    private InternalUserDto getCurrentCasUser() {
        try {
            Pac4jAuthentication token = (Pac4jAuthentication) SecurityContextHolder.getContext().getAuthentication();
            CommonProfile userProfile = token.getProfile();
            var userDto = new InternalUserDto();
            userDto.setLogin(userProfile.getUsername());
            userDto.setEmail(userProfile.getAttribute("email") != null ?
                userProfile.getAttribute("email").toString() : "");
            userDto.setFirstName(userProfile.getAttribute("firstName") != null ?
                userProfile.getAttribute("firstName").toString() : "");
            userDto.setLastName(userProfile.getAttribute("lastName") != null ?
                userProfile.getAttribute("lastName").toString(): "");
            userDto.setActivated(true);
            userDto.setAuthorities(getGeneralAuthorities());
            return userDto;
        } catch (Exception e) {
            log.error("Could not create user DTO with CAS attributes");
            log.debug(e.getMessage());
            return null;
        }
    }

    private InternalUserDto getCurrentLdapUser() {
        try {
            LdapUserDetails userDetails = (LdapUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            var userDto = new InternalUserDto();
            userDto.setLogin(userDetails.getUsername());
            userDto.setEmail("");
            userDto.setFirstName(userDetails.getUsername());
            userDto.setLastName("");
            userDto.setActivated(true);
            userDto.setAuthorities(userDetails.getAuthorities().stream()
                    .map(authority -> this.ldapAuthorityMapper.toDto((LdapAuthority)authority))
                .collect(Collectors.toSet()));
            return userDto;
        } catch (Exception e) {
            log.error("Could not create user DTO with LDAP attributes");
            log.debug(e.getMessage());
            return null;
        }
    }

    private InternalUserDto getCurrentOidcUser() {
        if (!SecurityUtils.isOidcAuthentication()) {
            return null;
        }
        try {
            OidcUser oidcUser = (OidcUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            var userDto = new InternalUserDto();
            userDto.setLogin(oidcUser.getPreferredUsername());
            userDto.setFirstName(oidcUser.getGivenName() != null ?
                oidcUser.getGivenName() : "");
            userDto.setEmail(oidcUser.getEmail() != null ?
                oidcUser.getEmail() : "");
            userDto.setLastName(oidcUser.getFamilyName() != null ?
                oidcUser.getFamilyName() : "");
            userDto.setActivated(true);
            userDto.setAuthorities(oidcUser.getAuthorities().stream()
                .map(authority -> this.oidcAuthorityMapper.toDto(new OAuth2UserAuthority(authority.getAuthority(), oidcUser.getClaims())))
                .collect(Collectors.toSet())
            );
            return userDto;
        } catch (Exception e) {
            log.error("Could not create user DTO with OIDC attributes");
            log.debug(e.getMessage());
            return null;
        }
    }

    public Set<AuthorityDto> getGeneralAuthorities() {
        Set<AuthorityDto> authorities = new HashSet<>();
        var authority = new AuthorityDto();
        authority.setName(AuthoritiesConstants.FRONTEND_USER);
        authorities.add(authority);
        return authorities;
    }
}
