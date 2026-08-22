/**
 * Scope parsing and matching, built on @atproto/oauth-scopes.
 *
 * Scope tokens this version of `@atproto/oauth-scopes` cannot fully interpret
 * are dropped rather than rejected, matching the reference provider — see
 * {@link filterScope}. Permission-set includes (`include:NSID?aud=...`) are
 * resolved at authorize-time via an injected {@link PermissionSetResolver}
 * and expanded into concrete granular scopes inline before the auth code is
 * stored — so resource-server checks never need network access.
 */

import type { Nsid as AtcuteNsid } from "@atcute/lexicons/syntax";
import {
	IncludeScope,
	isAtprotoOauthScope,
	ScopeMissingError,
	ScopePermissionsTransition,
	ScopesSet,
} from "@atproto/oauth-scopes";
import type { PermissionSetResolver } from "./permission-sets.js";

export { IncludeScope, ScopeMissingError, ScopePermissionsTransition, ScopesSet };

/**
 * Resources known to the spec. Used in OAuth metadata advertisement.
 */
export const GRANULAR_RESOURCES = [
	"repo",
	"rpc",
	"blob",
	"account",
	"identity",
] as const;

/**
 * Legacy "transitional" scopes recognized for back-compat.
 *
 * `ScopePermissionsTransition` treats these as broad shims: `transition:generic`
 * covers everything except account perms, `transition:email` adds account:email,
 * `transition:chat.bsky` adds RPC for chat.bsky.
 */
export const TRANSITION_SCOPES = [
	"transition:generic",
	"transition:email",
	"transition:chat.bsky",
] as const;

/**
 * The base scope every atproto OAuth token must carry.
 */
export const ATPROTO_SCOPE = "atproto";

export class ScopeParseError extends Error {
	constructor(
		message: string,
		readonly scope: string,
	) {
		super(message);
		this.name = "ScopeParseError";
	}
}

export interface ParseScopeOptions {
	/**
	 * When true, well-formed `include:` scopes are accepted but not expanded —
	 * the returned ScopesSet may still contain them.
	 * Use this at authorize-time, then call {@link expandScope} to resolve
	 * the includes before storing.
	 *
	 * When false (default), `include:` scopes throw a ScopeParseError. Use
	 * this on already-expanded scope strings (e.g. when re-validating a
	 * stored token's scope).
	 */
	allowIncludes?: boolean;
}

/**
 * Drop every scope token this version of `@atproto/oauth-scopes` cannot fully
 * interpret, preserving the order of the survivors.
 *
 * Callers **must** store this filtered string rather than the raw request
 * value: a token we can't parse today would otherwise be persisted verbatim
 * and silently become a live permission once the scope library learns to
 * understand it — without ever having been shown on the consent screen. It
 * also keeps the `scope` member of the token response honest about what was
 * actually granted (RFC 6749 §5.1).
 */
export function filterScope(input: string | undefined | null): string {
	return (input ?? "")
		.split(" ")
		.filter(Boolean)
		.filter(isAtprotoOauthScope)
		.join(" ");
}

/**
 * Validate a space-separated scope string, ignoring uninterpretable tokens.
 * Returns the parsed ScopesSet of the surviving scopes.
 *
 * The set reflects the filtered input, so callers that persist or echo back a
 * scope string need {@link filterScope} on the same input — see its docs.
 */
export function parseScope(
	input: string | undefined | null,
	{ allowIncludes = false }: ParseScopeOptions = {},
): ScopesSet {
	const set = ScopesSet.fromString(filterScope(input) || undefined);

	if (!set.has(ATPROTO_SCOPE)) {
		throw new ScopeParseError(
			`Scope must include "${ATPROTO_SCOPE}"`,
			input ?? "",
		);
	}

	for (const scope of set) {
		if (scope === ATPROTO_SCOPE) continue;
		if ((TRANSITION_SCOPES as readonly string[]).includes(scope)) continue;
		if (scope.startsWith("include:") && !allowIncludes) {
			throw new ScopeParseError(
				`Permission sets cannot be requested in this context: ${scope}`,
				scope,
			);
		}
	}

	return set;
}

/**
 * Expand any `include:` scopes in the input by resolving each NSID against
 * the supplied {@link PermissionSetResolver} and replacing the include with
 * the bundle's concrete granular scopes (per the spec — only `repo:` / `rpc:`
 * inside the include's namespace authority are kept).
 *
 * Returns the rewritten space-separated scope string. Throws a
 * {@link ScopeParseError} when an include cannot be resolved.
 */
export async function expandScope(
	scope: string,
	resolver: PermissionSetResolver | undefined,
): Promise<string> {
	const tokens = scope.split(" ").filter(Boolean);
	const out = new Set<string>();

	for (const token of tokens) {
		if (!token.startsWith("include:")) {
			out.add(token);
			continue;
		}

		if (!resolver) {
			throw new ScopeParseError(
				`Permission sets are not supported: no resolver configured`,
				token,
			);
		}

		const include = IncludeScope.fromString(token);
		if (!include) {
			throw new ScopeParseError(`Malformed include scope: ${token}`, token);
		}

		let permissionSet;
		try {
			permissionSet = await resolver.resolve(
				include.nsid as unknown as AtcuteNsid,
			);
		} catch (err) {
			throw new ScopeParseError(
				`Failed to resolve permission set ${include.nsid}: ${
					err instanceof Error ? err.message : String(err)
				}`,
				token,
			);
		}

		if (!permissionSet) {
			throw new ScopeParseError(
				`Permission set ${include.nsid} is not a permission-set lexicon`,
				token,
			);
		}

		for (const expanded of include.toScopes(permissionSet)) {
			out.add(expanded);
		}
	}

	return Array.from(out).join(" ");
}

/**
 * Build a ScopePermissionsTransition for a token's stored scope string.
 *
 * The transitional flavor is the only one we hand out — it inherits all the
 * granular `allows*`/`assert*` methods from ScopePermissions and adds shims
 * so `transition:generic` etc. continue to work for legacy clients.
 */
export function permissionsFor(scope: string): ScopePermissionsTransition {
	return new ScopePermissionsTransition(scope);
}
