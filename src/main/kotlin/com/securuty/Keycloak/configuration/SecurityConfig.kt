package com.securuty.Keycloak.configuration

import com.fasterxml.jackson.databind.util.JSONPObject
import com.google.gson.Gson
import com.nimbusds.jose.shaded.gson.JsonObject
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.SecurityFilterChain
import java.util.*
import java.util.function.Function
import java.util.stream.Collectors
import java.util.stream.Stream


@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
class SecurityConfig {

    @Bean
    fun sucurity(http: HttpSecurity): SecurityFilterChain {
        return http.csrf { it.disable() }
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .oauth2ResourceServer { oauth -> oauth.jwt { it.jwtAuthenticationConverter(KeycloakJwtConverter()) } }
            .headers { headers -> headers.frameOptions { it.sameOrigin() } }
            .build()
    }

    class KeycloakJwtConverter : Converter<Jwt, AbstractAuthenticationToken> {
        private val authoritiesConverter: KeycloakAuthoritiesConverter = KeycloakAuthoritiesConverter()

        override fun convert(source: Jwt): AbstractAuthenticationToken {
            val jwtAuthenticationToken =
                JwtAuthenticationToken(source, extractAuthorities(source), extractPrincipal(source))
            return jwtAuthenticationToken
        }

        private fun extractPrincipal(source: Jwt): String {
            return source.getClaimAsString(JwtClaimNames.SUB);
        }

        private fun extractAuthorities(source: Jwt): Collection<GrantedAuthority>? {
            return this.authoritiesConverter.convert(source)
        }
    }

    class KeycloakAuthoritiesConverter : Converter<Jwt, Collection<GrantedAuthority>> {

        companion object {
            private const val REALM_ACCESS = "realm_access"
            private const val ROLES = "roles"
            private const val RESOURCE_ACCESS = "resource_access"
            private const val SEPARATOR = "_"
            private const val ROLE_PREFIX = "ROLE_"
        }

        override fun convert(jwt: Jwt): Collection<GrantedAuthority>? {
            val realmRoles = extractRealmRoles(jwt)
            val resourceRoles = extractResourceRoles(jwt)
            return Stream.concat<String>(realmRoles, resourceRoles)
                .map<SimpleGrantedAuthority> { role: String ->
                    SimpleGrantedAuthority(
                        KeycloakAuthoritiesConverter.ROLE_PREFIX + role.uppercase(Locale.getDefault())
                    )
                }
                .collect(Collectors.toSet<GrantedAuthority>())
        }

        private fun extractResourceRoles(jwt: Jwt): Stream<String> {
            val gson = Gson()

            val mapResource =
                Function<Map.Entry<String, Any>, Stream<String>> { (key, value1): Map.Entry<String, Any> ->
                    val value = gson.toJsonTree(value1, Map::class.java)
                    val roles =
                        value.asJsonObject[ROLES].asJsonArray.map { it.asString }
                    roles.stream()
                        .map<String> { role: String -> key + SEPARATOR + role }
                }
            val mapResources =
                Function<Set<Map.Entry<String, Any>>, Collection<String>> { resources: Set<Map.Entry<String, Any>> ->
                    resources.stream()
                        .flatMap(mapResource)
                        .toList()
                }
            return Optional.ofNullable<Map<String, Any>>(jwt.getClaimAsMap(RESOURCE_ACCESS))
                .map<Set<Map.Entry<String, Any>>> { resources: Map<String, Any> -> resources.entries }
                .map<Collection<String>>(mapResources)
                .orElse(emptyList<String>())
                .stream()
        }

        private fun extractRealmRoles(jwt: Jwt): Stream<String> {
            return Optional.ofNullable<Map<String?, Any?>>(jwt.getClaimAsMap(KeycloakAuthoritiesConverter.REALM_ACCESS))
                .map<Collection<String>?> { resource: Map<String?, Any?> ->
                    resource[KeycloakAuthoritiesConverter.ROLES] as Collection<String>?
                }
                .orElse(emptyList<String>())
                .stream()
        }

    }

}