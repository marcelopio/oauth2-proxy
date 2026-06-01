package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
)

const keycloakOIDCProviderName = "Keycloak OIDC"

// KeycloakOIDCProvider creates a Keycloak provider based on OIDCProvider
type KeycloakOIDCProvider struct {
	*OIDCProvider
	useRPT bool
}

// NewKeycloakOIDCProvider makes a KeycloakOIDCProvider using the ProviderData
func NewKeycloakOIDCProvider(p *ProviderData, opts options.Provider) *KeycloakOIDCProvider {
	p.setProviderDefaults(providerDefaults{
		name: keycloakOIDCProviderName,
	})

	provider := &KeycloakOIDCProvider{
		OIDCProvider: NewOIDCProvider(p, opts.OIDCConfig),
		useRPT:       ptr.Deref(opts.KeycloakConfig.UseRPTToken, false),
	}

	provider.addAllowedRoles(opts.KeycloakConfig.Roles)
	return provider
}

var _ Provider = (*KeycloakOIDCProvider)(nil)

// addAllowedRoles sets Keycloak roles that are authorized.
// Assumes `SetAllowedGroups` is already called on groups and appends to that
// with `role:` prefixed roles.
func (p *KeycloakOIDCProvider) addAllowedRoles(roles []string) {
	if p.AllowedGroups == nil {
		p.AllowedGroups = make(map[string]struct{})
	}
	for _, role := range roles {
		p.AllowedGroups[formatRole(role)] = struct{}{}
	}
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *KeycloakOIDCProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	ss, err := p.OIDCProvider.CreateSessionFromToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("could not create session from token: %v", err)
	}

	// Extract custom keycloak roles and enrich session
	if err := p.extractRoles(ss); err != nil {
		return nil, err
	}

	return ss, nil
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *KeycloakOIDCProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	err := p.OIDCProvider.EnrichSession(ctx, s)
	if err != nil {
		return fmt.Errorf("could not enrich oidc session: %v", err)
	}
	if err := p.extractRoles(s); err != nil {
		return err
	}

	if p.useRPT {
		rpt, expiry, err := p.obtainRPT(ctx, s.AccessToken)
		if err != nil {
			return fmt.Errorf("unable to obtain RPT: %v", err)
		}
		s.AccessToken = rpt
		p.addRPTPermissions(s)
		s.CreatedAtNow()
		s.SetExpiresOn(expiry)
	}

	return nil
}

// RefreshSession adds role extraction logic to the refresh flow
func (p *KeycloakOIDCProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	refreshed, err := p.OIDCProvider.RefreshSession(ctx, s)

	// Refresh could have failed or there was not session to refresh (with no error raised)
	if err != nil || !refreshed {
		return refreshed, err
	}

	if err := p.extractRoles(s); err != nil {
		return true, err
	}

	if p.useRPT {
		rpt, expiry, err := p.obtainRPT(ctx, s.AccessToken)
		if err != nil {
			return true, fmt.Errorf("unable to obtain RPT on refresh: %v", err)
		}
		s.AccessToken = rpt
		p.addRPTPermissions(s)
		s.CreatedAtNow()
		s.SetExpiresOn(expiry)
	}

	return true, nil
}

// obtainRPT exchanges a PAT for a Keycloak UMA RPT using the token endpoint
func (p *KeycloakOIDCProvider) obtainRPT(ctx context.Context, pat string) (string, time.Time, error) {
	if pat == "" {
		return "", time.Time{}, fmt.Errorf("missing PAT for RPT exchange")
	}

	params := url.Values{}
	params.Add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	if p.ClientID != "" {
		params.Add("audience", p.ClientID)
	}

	var respBody struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	// POST form to token endpoint with Authorization: Bearer <PAT>
	err := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", tokenTypeBearer+" "+pat).
		Do().
		UnmarshalInto(&respBody)
	if err != nil {
		logger.Errorf("RPT exchange request failed: %v", err)
		return "", time.Time{}, err
	}

	if respBody.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("RPT exchange did not return access_token")
	}

	expiry := time.Now().Add(time.Duration(respBody.ExpiresIn) * time.Second)
	return respBody.AccessToken, expiry, nil
}

func (p *KeycloakOIDCProvider) extractRoles(s *sessions.SessionState) error {
	claims, err := p.getAccessClaims(s)
	if err != nil {
		return err
	}

	//nolint:prealloc
	var roles []string
	roles = append(roles, claims.RealmAccess.Roles...)
	roles = append(roles, getClientRoles(claims)...)

	// Add to groups list with `role:` prefix to distinguish from groups
	for _, role := range roles {
		s.Groups = append(s.Groups, formatRole(role))
	}
	return nil
}

type realmAccess struct {
	Roles []string `json:"roles"`
}

type accessClaims struct {
	RealmAccess    realmAccess            `json:"realm_access"`
	ResourceAccess map[string]interface{} `json:"resource_access"`
	Authorization  authorizationClaims    `json:"authorization"`
}

type authorizationClaims struct {
	Permissions []authorizationPermission `json:"permissions"`
}

type authorizationPermission struct {
	RSID   string   `json:"rsid"`
	RSName string   `json:"rsname"`
	Scopes []string `json:"scopes"`
}

func (p *KeycloakOIDCProvider) getAccessClaims(s *sessions.SessionState) (*accessClaims, error) {
	parts := strings.Split(s.AccessToken, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed access token, expected 3 parts got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed access token, couldn't extract jwt payload: %v", err)
	}

	var claims accessClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func (p *KeycloakOIDCProvider) addRPTPermissions(s *sessions.SessionState) {
	claims, err := p.getAccessClaims(s)
	if err != nil {
		logger.Printf("unable to extract RPT permissions: %v", err)
		return
	}

	if len(claims.Authorization.Permissions) == 0 {
		return
	}

	if s.AdditionalClaims == nil {
		s.AdditionalClaims = make(map[string]interface{})
	}

	s.AdditionalClaims["permissions"] = claims.Authorization.Permissions
}

// getClientRoles extracts client roles from the `resource_access` claim with
// the format `client:role`.
//
// ResourceAccess format:
//
//	"resource_access": {
//	  "clientA": {
//	    "roles": [
//	      "roleA"
//	    ]
//	  },
//	  "clientB": {
//	    "roles": [
//	      "roleA",
//	      "roleB",
//	      "roleC"
//	    ]
//	  }
//	}
func getClientRoles(claims *accessClaims) []string {
	var clientRoles []string
	for clientName, access := range claims.ResourceAccess {
		accessMap, ok := access.(map[string]interface{})
		if !ok {
			continue
		}

		var roles interface{}
		if roles, ok = accessMap["roles"]; !ok {
			continue
		}
		for _, role := range roles.([]interface{}) {
			clientRoles = append(clientRoles, fmt.Sprintf("%s:%s", clientName, role))
		}
	}
	return clientRoles
}

func formatRole(role string) string {
	return fmt.Sprintf("role:%s", role)
}
