package org.appsec.securityrat.provider;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import org.appsec.securityrat.api.dto.AuditEventDto;
import org.appsec.securityrat.api.dto.AuthenticationConfigDto;
import org.appsec.securityrat.api.dto.AuthenticationConfigDto.Type;
import org.appsec.securityrat.api.dto.AuthorityDto;
import org.appsec.securityrat.api.dto.LoggerDto;
import org.appsec.securityrat.api.provider.SystemInfo;
import org.appsec.securityrat.config.ApplicationProperties;
import org.appsec.securityrat.config.ApplicationProperties.Authentication;
import org.appsec.securityrat.config.ApplicationProperties.Cas;
import org.appsec.securityrat.config.ApplicationProperties.Oidc;
import org.appsec.securityrat.config.audit.AuditEventConverter;
import org.appsec.securityrat.domain.PersistentAuditEvent;
import org.appsec.securityrat.provider.mapper.AuditEventMapper;
import org.appsec.securityrat.provider.mapper.AuthorityMapper;
import org.appsec.securityrat.provider.mapper.LoggerMapper;
import org.appsec.securityrat.repository.AuthorityRepository;
import org.appsec.securityrat.repository.PersistenceAuditEventRepository;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.inject.Inject;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SystemInfoImpl implements SystemInfo {
    @Inject
    private ApplicationProperties appProps;

    @Inject
    private AuditEventConverter auditEventConverter;

    // Repositories

    @Inject
    private AuthorityRepository authorityRepo;

    @Inject
    private PersistenceAuditEventRepository persistenceAuditEventRepository;

    @Inject
    private ClientRegistrationRepository clientRegistrationRepository;

    // Mappers

    @Inject
    private AuthorityMapper authorityMapper;

    @Inject
    private LoggerMapper loggerMapper;

    @Inject
    private AuditEventMapper auditEventMapper;

    @Override
    @Transactional
    public List<AuthorityDto> getAuthorities() {
        return this.authorityRepo.findAll()
                .stream()
                .map(this.authorityMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    public AuthenticationConfigDto getAuthenticationConfig() {
        Authentication auth = this.appProps.getAuthentication();
        Cas cas = this.appProps.getCas();
        Oidc oidc = this.appProps.getOidc();

        AuthenticationConfigDto result = new AuthenticationConfigDto();

        switch (auth.getType()) {
            case CAS:
                result.setType(Type.CAS);
                break;

            case FORM:
                result.setType(Type.FORM);
                break;

            case LDAP:
                result.setType(Type.LDAP);
                break;

            case OIDC:
                result.setType(Type.OIDC);
                break;

            default:
                throw new UnsupportedOperationException(
                        "Authentication type not implemented: "
                                + auth.getType());
        }

        result.setRegistration(auth.isRegistration());
        result.setCasLogout(cas.getLogoutUrl().toExternalForm());
        result.setOidcClientId(oidc.getClientId());
        result.setOidcRegistrationId(getOidcRegistrationId());

        return result;
    }

    @Override
    public List<LoggerDto> getLoggers() {
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();

        return ctx.getLoggerList()
                .stream()
                .map(this.loggerMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    public void updateLogger(LoggerDto logger) {
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();

        ctx.getLogger(logger.getName())
                .setLevel(Level.valueOf(logger.getLevel()));
    }

    @Override
    @Transactional
    public List<AuditEventDto> getAuditEvents() {
        return this.auditEventConverter.convertToAuditEvent(
                this.persistenceAuditEventRepository.findAll())
                .stream()
                .map(this.auditEventMapper::toDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public List<AuditEventDto> getAuditEvents(
            Instant fromDate,
            Instant toDate) {
        List<PersistentAuditEvent> events =
                this.persistenceAuditEventRepository.findAllByAuditEventDateBetween(
                        fromDate,
                        toDate);

        return this.auditEventConverter.convertToAuditEvent(events)
                .stream()
                .map(this.auditEventMapper::toDto)
                .collect(Collectors.toList());
    }

    private String getOidcRegistrationId() {
        ClientRegistration standardRegistration = this.clientRegistrationRepository.findByRegistrationId("oidc");
        if (standardRegistration != null) {
            return standardRegistration.getRegistrationId();
        }
        if (this.clientRegistrationRepository instanceof Iterable) {
            for (Object entry : (Iterable<?>) this.clientRegistrationRepository) {
                if (entry instanceof ClientRegistration) {
                    return ((ClientRegistration) entry).getRegistrationId();
                }
            }
        }
        return null;
    }
}
