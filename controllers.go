package magitrickle

import (
	"encoding/json"
	"net/http"

	"magitrickle/pkg/magitrickle-api/types"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// apiNetfilterDHook
func (a *App) apiNetfilterDHook(w http.ResponseWriter, r *http.Request) {
	var nfh types.NetfilterDHookReq
	err := json.NewDecoder(r.Body).Decode(&nfh)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	log.Debug().Str("type", nfh.Type).Str("table", nfh.Table).Msg("netfilter.d event")
	err = a.dnsOverrider.NetfilterDHook(nfh.Type, nfh.Table)
	if err != nil {
		log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
	}
	for _, group := range a.groups {
		err := group.NetfilterDHook(nfh.Type, nfh.Table)
		if err != nil {
			log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
		}
	}
}

func (a *App) apiHandler() http.Handler {
	r := chi.NewRouter()
	r.Post("/api/v1/system/hooks/netfilterd", a.apiNetfilterDHook)
	return r
}
