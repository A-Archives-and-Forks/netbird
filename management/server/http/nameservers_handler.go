package http

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// NameserversHandler is the nameserver group handler of the account
type NameserversHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewNameserversHandler returns a new instance of NameserversHandler handler
func NewNameserversHandler(accountManager server.AccountManager, authCfg AuthCfg) *NameserversHandler {
	return &NameserversHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllNameservers returns the list of nameserver groups for the account
func (h *NameserversHandler) GetAllNameservers(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	nsGroups, err := h.accountManager.ListNameServerGroups(r.Context(), claims.AccountId, claims.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiNameservers := make([]*api.NameserverGroup, 0)
	for _, r := range nsGroups {
		apiNameservers = append(apiNameservers, toNameserverGroupResponse(r))
	}

	util.WriteJSONObject(r.Context(), w, apiNameservers)
}

// CreateNameserverGroup handles nameserver group creation request
func (h *NameserversHandler) CreateNameserverGroup(w http.ResponseWriter, r *http.Request) {
	var req api.PostApiDnsNameserversJSONRequestBody
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	nsList, err := toServerNSList(req.Nameservers)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid NS servers format"), w)
		return
	}

	claims := h.claimsExtractor.FromRequestContext(r)
	nsGroup, err := h.accountManager.CreateNameServerGroup(r.Context(), claims.AccountId, req.Name, req.Description,
		nsList, req.Groups, req.Primary, req.Domains, req.Enabled, claims.UserId, req.SearchDomainsEnabled,
	)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// UpdateNameserverGroup handles update to a nameserver group identified by a given ID
func (h *NameserversHandler) UpdateNameserverGroup(w http.ResponseWriter, r *http.Request) {
	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	var req api.PutApiDnsNameserversNsgroupIdJSONRequestBody
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	nsList, err := toServerNSList(req.Nameservers)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid NS servers format"), w)
		return
	}

	updatedNSGroup := &nbdns.NameServerGroup{
		ID:                   nsGroupID,
		Name:                 req.Name,
		Description:          req.Description,
		Primary:              req.Primary,
		Domains:              req.Domains,
		NameServers:          nsList,
		Groups:               req.Groups,
		Enabled:              req.Enabled,
		SearchDomainsEnabled: req.SearchDomainsEnabled,
	}

	claims := h.claimsExtractor.FromRequestContext(r)
	err = h.accountManager.SaveNameServerGroup(r.Context(), claims.AccountId, claims.UserId, updatedNSGroup)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(updatedNSGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// DeleteNameserverGroup handles nameserver group deletion request
func (h *NameserversHandler) DeleteNameserverGroup(w http.ResponseWriter, r *http.Request) {
	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	claims := h.claimsExtractor.FromRequestContext(r)
	err := h.accountManager.DeleteNameServerGroup(r.Context(), claims.AccountId, nsGroupID, claims.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, emptyObject{})
}

// GetNameserverGroup handles a nameserver group Get request identified by ID
func (h *NameserversHandler) GetNameserverGroup(w http.ResponseWriter, r *http.Request) {
	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	claims := h.claimsExtractor.FromRequestContext(r)
	nsGroup, err := h.accountManager.GetNameServerGroup(r.Context(), claims.AccountId, claims.UserId, nsGroupID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

func toServerNSList(apiNSList []api.Nameserver) ([]nbdns.NameServer, error) {
	var nsList []nbdns.NameServer
	for _, apiNS := range apiNSList {
		parsed, err := nbdns.ParseNameServerURL(fmt.Sprintf("%s://%s:%d", apiNS.NsType, apiNS.Ip, apiNS.Port))
		if err != nil {
			return nil, err
		}
		nsList = append(nsList, parsed)
	}

	return nsList, nil
}

func toNameserverGroupResponse(serverNSGroup *nbdns.NameServerGroup) *api.NameserverGroup {
	var nsList []api.Nameserver
	for _, ns := range serverNSGroup.NameServers {
		apiNS := api.Nameserver{
			Ip:     ns.IP.String(),
			NsType: api.NameserverNsType(ns.NSType.String()),
			Port:   ns.Port,
		}
		nsList = append(nsList, apiNS)
	}

	return &api.NameserverGroup{
		Id:                   serverNSGroup.ID,
		Name:                 serverNSGroup.Name,
		Description:          serverNSGroup.Description,
		Primary:              serverNSGroup.Primary,
		Domains:              serverNSGroup.Domains,
		Groups:               serverNSGroup.Groups,
		Nameservers:          nsList,
		Enabled:              serverNSGroup.Enabled,
		SearchDomainsEnabled: serverNSGroup.SearchDomainsEnabled,
	}
}
