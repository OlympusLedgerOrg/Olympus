//! Shared route constants for admin mutation policy.

pub const ADMIN_SCOPE: &str = "admin";

pub const ADMIN_SHARDS: &str = "/admin/shards";
pub const ADMIN_USERS: &str = "/admin/users";
pub const ADMIN_USER_KEYS: &str = "/admin/users/{user_id}/keys";
pub const ADMIN_USER_ROLE: &str = "/admin/users/{user_id}/role";
pub const ADMIN_KEY_SCOPES: &str = "/admin/keys/{key_id}/scopes";
pub const ADMIN_KEY: &str = "/admin/keys/{key_id}";

pub const AUTH_REGISTER: &str = "/auth/register";
pub const AUTH_LOGIN: &str = "/auth/login";
pub const AUTH_REISSUE_KEY: &str = "/auth/reissue-key";
pub const AUTH_KEYS: &str = "/auth/keys";
pub const AUTH_KEY: &str = "/auth/keys/{key_id}";
pub const AUTH_ME: &str = "/auth/me";
pub const AUTH_ADMIN_USERS: &str = "/auth/admin/users";
pub const AUTH_ADMIN_USER: &str = "/auth/admin/users/{user_id}";
pub const AUTH_RECOVERY_REQUEST: &str = "/auth/recovery/request";
pub const AUTH_RECOVERY_COMPLETE: &str = "/auth/recovery/complete";

pub const KEY_ADMIN_GENERATE: &str = "/key/admin/generate";
pub const KEY_ADMIN_RELOAD_KEYS: &str = "/key/admin/reload-keys";
pub const KEY_SIGNING: &str = "/key/signing";
pub const KEY_SIGNING_KEY: &str = "/key/signing/{key_id}";
pub const KEY_SIGNING_DEV_GENERATE: &str = "/key/signing/dev-generate";

pub const FEDERATION_PEERS: &str = "/federation/peers";
pub const FEDERATION_PEER: &str = "/federation/peers/{peer_id}";
pub const FEDERATION_PEER_TRUST: &str = "/federation/peers/{peer_id}/trust";
pub const FEDERATION_CHECKPOINTS: &str = "/federation/checkpoints";
pub const FEDERATION_STATUS: &str = "/federation/status";
pub const FEDERATION_IDENTITY_ROTATE: &str = "/federation/identity/rotate";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedAdminMutationRoute {
    pub method: &'static str,
    pub path_pattern: &'static str,
    pub scope: &'static str,
}

pub const SIGNED_ADMIN_MUTATION_ROUTES: &[SignedAdminMutationRoute] = &[
    SignedAdminMutationRoute {
        method: "POST",
        path_pattern: ADMIN_SHARDS,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "POST",
        path_pattern: ADMIN_USER_KEYS,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "PATCH",
        path_pattern: ADMIN_USER_ROLE,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "PATCH",
        path_pattern: ADMIN_KEY_SCOPES,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "DELETE",
        path_pattern: ADMIN_KEY,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "POST",
        path_pattern: AUTH_ADMIN_USERS,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "DELETE",
        path_pattern: AUTH_ADMIN_USER,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "POST",
        path_pattern: KEY_ADMIN_GENERATE,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "POST",
        path_pattern: KEY_ADMIN_RELOAD_KEYS,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "POST",
        path_pattern: FEDERATION_PEERS,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "DELETE",
        path_pattern: FEDERATION_PEER,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "PUT",
        path_pattern: FEDERATION_PEER_TRUST,
        scope: ADMIN_SCOPE,
    },
    SignedAdminMutationRoute {
        method: "POST",
        path_pattern: FEDERATION_IDENTITY_ROTATE,
        scope: ADMIN_SCOPE,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_ADMIN_SCOPE_MUTATIONS: &[(&str, &str)] = &[
        ("POST", ADMIN_SHARDS),
        ("POST", ADMIN_USER_KEYS),
        ("PATCH", ADMIN_USER_ROLE),
        ("PATCH", ADMIN_KEY_SCOPES),
        ("DELETE", ADMIN_KEY),
        ("POST", AUTH_ADMIN_USERS),
        ("DELETE", AUTH_ADMIN_USER),
        ("POST", KEY_ADMIN_GENERATE),
        ("POST", KEY_ADMIN_RELOAD_KEYS),
        ("POST", FEDERATION_PEERS),
        ("DELETE", FEDERATION_PEER),
        ("PUT", FEDERATION_PEER_TRUST),
        ("POST", FEDERATION_IDENTITY_ROTATE),
    ];

    #[test]
    fn signed_admin_mutation_routes_cover_admin_scope_mutation_routes() {
        assert_eq!(
            SIGNED_ADMIN_MUTATION_ROUTES.len(),
            EXPECTED_ADMIN_SCOPE_MUTATIONS.len(),
            "SIGNED_ADMIN_MUTATION_ROUTES must stay in lockstep with admin-scope mutation routes",
        );

        for (method, path_pattern) in EXPECTED_ADMIN_SCOPE_MUTATIONS {
            let route = SIGNED_ADMIN_MUTATION_ROUTES
                .iter()
                .find(|route| route.method == *method && route.path_pattern == *path_pattern)
                .unwrap_or_else(|| {
                    panic!("missing signed-admin policy for {method} {path_pattern}")
                });
            assert_eq!(
                route.scope, ADMIN_SCOPE,
                "signed-admin policy for {method} {path_pattern} must require ADMIN_SCOPE",
            );
        }

        for route in SIGNED_ADMIN_MUTATION_ROUTES {
            assert!(
                EXPECTED_ADMIN_SCOPE_MUTATIONS
                    .iter()
                    .any(|(method, path_pattern)| {
                        route.method == *method && route.path_pattern == *path_pattern
                    }),
                "unexpected signed-admin policy for {} {}",
                route.method,
                route.path_pattern,
            );
        }
    }
}
