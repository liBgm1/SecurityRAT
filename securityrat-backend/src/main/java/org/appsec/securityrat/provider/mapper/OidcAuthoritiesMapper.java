package org.appsec.securityrat.provider.mapper;

import org.appsec.securityrat.config.ApplicationProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.inject.Inject;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.io.IOException;

@Component
public class OidcAuthoritiesMapper {

    private final ApplicationProperties appConfig;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    public OidcAuthoritiesMapper(ApplicationProperties appConfig) {
        this.appConfig = appConfig;
    }

    public Set<GrantedAuthority> mapAuthorities(OidcUser oidcUser, OAuth2AccessToken accessToken) {
        if (oidcUser == null) {
            return Collections.emptySet();
        }

        Map<String, Object> userClaims = oidcUser.getClaims();
        List<String> authorities = resolveAuthorities(userClaims, accessToken);

        return authorities.stream()
            .filter(StringUtils::hasText)
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toSet());
    }

    private List<String> resolveAuthorities(Map<String, Object> userClaims, OAuth2AccessToken accessToken) {
        Map<String, Object> accessClaims = parseAccessTokenClaims(accessToken);
        String claimPath = appConfig.getOidc().getRolesClaimPath();
        List<String> roles = Collections.emptyList();
        if (accessClaims != null) {
            roles = resolveClaimValues(accessClaims, claimPath);
        }
        if (roles.isEmpty()) {
            roles = resolveClaimValues(userClaims, claimPath);
        }
        return roles;
    }

    private Map<String, Object> parseAccessTokenClaims(OAuth2AccessToken accessToken) {
        if (accessToken == null || !StringUtils.hasText(accessToken.getTokenValue())) {
            return null;
        }
        String token = accessToken.getTokenValue();
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            return null;
        }
        String payload = parts[1];
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(payload);
            String json = new String(decoded, StandardCharsets.UTF_8);
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = MAPPER.readValue(json, Map.class);
            return claims;
        } catch (IllegalArgumentException | IOException e) {
            return null;
        }
    }

    private List<String> resolveClaimValues(Map<String, Object> claims, String claimPath) {
        Object value = resolveClaimValue(claims, claimPath);
        if (value == null) {
            return Collections.emptyList();
        }

        if (value instanceof String) {
            return splitStringValues((String) value);
        }

        if (value instanceof Collection) {
            return ((Collection<?>) value).stream()
                .filter(Objects::nonNull)
                .map(Object::toString)
                .flatMap(item -> splitStringValues(item).stream())
                .collect(Collectors.toList());
        }

        if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            List<String> results = new ArrayList<>(length);
            for (int i = 0; i < length; i++) {
                Object element = Array.get(value, i);
                if (element != null) {
                    results.addAll(splitStringValues(element.toString()));
                }
            }
            return results;
        }

        return splitStringValues(value.toString());
    }

    private Object resolveClaimValue(Map<String, Object> claims, String claimPath) {
        if (!StringUtils.hasText(claimPath) || claims == null) {
            return null;
        }

        String[] segments = claimPath.split("\\.");
        Object current = claims;
        for (String segment : segments) {
            if (!(current instanceof Map)) {
                return null;
            }
            current = ((Map<?, ?>) current).get(segment);
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    private List<String> splitStringValues(String value) {
        if (!StringUtils.hasText(value)) {
            return Collections.emptyList();
        }

        String trimmed = value.trim();
        if (trimmed.contains(" ")) {
            return splitByDelimiter(trimmed, " ");
        }
        if (trimmed.contains(",")) {
            return splitByDelimiter(trimmed, ",");
        }
        return Collections.singletonList(trimmed);
    }

    private List<String> splitByDelimiter(String value, String delimiter) {
        String[] parts = value.split(delimiter);
        List<String> results = new ArrayList<>(parts.length);
        for (String part : parts) {
            if (StringUtils.hasText(part)) {
                results.add(part.trim());
            }
        }
        return results;
    }
}
