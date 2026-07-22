package org.appsec.securityrat.provider.mapper;

import org.appsec.securityrat.api.dto.AuthorityDto;
import org.mapstruct.Mapper;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;


@Mapper(componentModel = "spring")
public abstract class OidcAuthorityMapper {

    public AuthorityDto toDto(OAuth2UserAuthority authority){
            if ( authority == null ) {
                return null;
            }
            AuthorityDto authorityDto = new AuthorityDto();
            authorityDto.setName( authority.getAuthority() );
            return authorityDto;
    }
}
