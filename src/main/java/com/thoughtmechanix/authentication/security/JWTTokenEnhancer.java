package com.thoughtmechanix.authentication.security;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import com.thoughtmechanix.authentication.model.UserOrganization;
import com.thoughtmechanix.authentication.repository.OrgUserRepository;

public class JWTTokenEnhancer implements TokenEnhancer {

	@Autowired
	private OrgUserRepository orgUserRepository;

	private String getOrgId(String userName) {
		UserOrganization orgUser = orgUserRepository.findByUserName(userName);
		return orgUser.getOrganizationId();
	}

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		Map<String, Object> additinalInfo = new HashMap<>();
		String orgId = getOrgId(authentication.getName());

		additinalInfo.put("organizationId", orgId);
		((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additinalInfo);

		return accessToken;
	}

}
