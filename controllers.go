package magitrickle

import (
	"encoding/json"
	"net/http"
	"strconv"

	"magitrickle/models"
	"magitrickle/pkg/magitrickle-api/types"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

// apiNetfilterDHook
//
//	@Summary		Хук эвента netfilter.d
//	@Description	Эмитирует хук эвента netfilter.d
//	@Tags			hooks
//	@Accept			json
//	@Produce		json
//	@Param			json	body	types.NetfilterDHookReq	true	"Тело запроса"
//	@Success		200
//	@Failure		400	{object}	types.ErrorRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/system/hooks/netfilterd [post]
func (a *App) apiNetfilterDHook(w http.ResponseWriter, r *http.Request) {
	var req types.NetfilterDHookReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
	}
	log.Debug().Str("type", req.Type).Str("table", req.Table).Msg("netfilter.d event")
	err = a.dnsOverrider.NetfilterDHook(req.Type, req.Table)
	if err != nil {
		log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
	}
	for _, group := range a.groups {
		err := group.NetfilterDHook(req.Type, req.Table)
		if err != nil {
			log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
		}
	}
}

// apiGetGroups
//
//	@Summary		Получить список групп
//	@Description	Возвращает список групп
//	@Tags			groups
//	@Produce		json
//	@Param			with_rules	query		bool	false	"Возвращать группы с их правилами"
//	@Success		200			{object}	types.GroupsRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups [get]
func (a *App) apiGetGroups(w http.ResponseWriter, r *http.Request) {
	withRules := r.URL.Query().Get("with_rules") == "true"
	groups := make([]*models.Group, len(a.groups))
	for idx, group := range a.groups {
		groups[idx] = group.Group
	}
	writeJson(w, http.StatusOK, toGroupsRes(groups, withRules))
}

// apiGetGroup
//
//	@Summary		Получить группу
//	@Description	Возвращает запрошенную группу
//	@Tags			groups
//	@Produce		json
//	@Param			groupID		path		string	true	"ID группы"
//	@Param			with_rules	query		bool	false	"Возвращать группу с её правилами"
//	@Success		200			{object}	types.GroupRes
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID} [get]
func (a *App) apiGetGroup(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	withRules := r.URL.Query().Get("with_rules") == "true"
	writeJson(w, http.StatusOK, toGroupRes(a.groups[groupIdx].Group, withRules))
}

// apiGetRules
//
//	@Summary		Получить список правил
//	@Description	Возвращает список правил
//	@Tags			rules
//	@Produce		json
//	@Param			groupID	path		string	true	"ID группы"
//	@Success		200		{object}	types.RulesRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules [get]
func (a *App) apiGetRules(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	writeJson(w, http.StatusOK, toRulesRes(a.groups[groupIdx].Group.Rules))
}

// apiGetRule
//
//	@Summary		Получить правило
//	@Description	Возвращает запрошенное правило
//	@Tags			rules
//	@Produce		json
//	@Param			groupID	path		string	true	"ID группы"
//	@Param			ruleID	path		string	true	"ID правила"
//	@Success		200		{object}	types.RuleRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules/{ruleID} [get]
func (a *App) apiGetRule(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	writeJson(w, http.StatusOK, toRuleRes(a.groups[groupIdx].Group.Rules[ruleIdx]))
}

func (a *App) apiHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/groups", func(r chi.Router) {
			r.Get("/", a.apiGetGroups)
			r.Route("/{groupID}", func(r chi.Router) {
				r.Use(func(next http.Handler) http.Handler {
					fn := func(w http.ResponseWriter, r *http.Request) {
						groupID := chi.URLParam(r, "groupID")
						id, err := types.ParseID(groupID)
						if err != nil {
							writeError(w, http.StatusBadRequest, "invalid group id")
							return
						}
						for idx, group := range a.groups {
							if group.ID == id {
								r.Header.Set("groupIdx", strconv.Itoa(idx))
								next.ServeHTTP(w, r)
								return
							}
						}
						writeError(w, http.StatusNotFound, "group not exist")
						return
					}
					return http.HandlerFunc(fn)
				})
				r.Get("/", a.apiGetGroup)
				r.Route("/rules", func(r chi.Router) {
					r.Get("/", a.apiGetRules)
					r.Route("/{ruleID}", func(r chi.Router) {
						r.Use(func(next http.Handler) http.Handler {
							fn := func(w http.ResponseWriter, r *http.Request) {
								groupID := chi.URLParam(r, "ruleID")
								id, err := types.ParseID(groupID)
								if err != nil {
									writeError(w, http.StatusBadRequest, "invalid rule id")
									return
								}
								groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))

								for idx, rule := range a.groups[groupIdx].Rules {
									if rule.ID == id {
										r.Header.Set("ruleIdx", strconv.Itoa(idx))
										next.ServeHTTP(w, r)
										return
									}
								}
								writeError(w, http.StatusNotFound, "rule not exist")
								return
							}
							return http.HandlerFunc(fn)
						})
						r.Get("/", a.apiGetRule)
					})
				})
			})
		})
		r.Route("/system", func(r chi.Router) {
			r.Route("/hooks", func(r chi.Router) {
				r.Post("/netfilterd", a.apiNetfilterDHook)
			})
		})
	})

	return r
}
