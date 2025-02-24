package magitrickle

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"magitrickle/models"
	"magitrickle/pkg/magitrickle-api/types"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
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
	req, err := readJson[types.NetfilterDHookReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Debug().Str("type", req.Type).Str("table", req.Table).Msg("netfilter.d event")
	err = a.dnsOverrider.NetfilterDHook(req.Type, req.Table)
	if err != nil {
		log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
	}
	for _, groupWrapper := range a.groups {
		err := groupWrapper.NetfilterDHook(req.Type, req.Table)
		if err != nil {
			log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
		}
	}
}

// apiListInterfaces
//
//	@Summary		Получить список интерфейсов
//	@Description	Возвращает список интерфейсов
//	@Tags			config
//	@Produce		json
//	@Success		200 {object}    types.InterfacesRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/system/interfaces [get]
func (a *App) apiListInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces, err := a.ListInterfaces()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to get interfaces: %w", err).Error())
		return
	}
	interfacesRes := make([]types.InterfaceRes, len(interfaces))
	for i, iface := range interfaces {
		interfacesRes[i] = types.InterfaceRes{ID: iface.Name}
	}
	writeJson(w, http.StatusOK, types.InterfacesRes{Interfaces: interfacesRes})
}

// apiSaveConfig
//
//	@Summary		Сохранить конфигурацию
//	@Description	Сохраняет текущую конфигурацию в постоянную память
//	@Tags			config
//	@Produce		json
//	@Success		200
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/system/config/save [post]
func (a *App) apiSaveConfig(w http.ResponseWriter, r *http.Request) {
	out, err := yaml.Marshal(a.ExportConfig())
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("failed to marshal config file: %w", err).Error())
		return
	}
	err = os.MkdirAll(cfgFolderLocation, os.ModePerm)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("failed to create config folder: %w", err).Error())
		return
	}
	err = os.WriteFile(cfgFileLocation, out, 0600)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("failed to write config file: %w", err).Error())
		return
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
	for i, groupWrapper := range a.groups {
		groups[i] = groupWrapper.Group
	}
	writeJson(w, http.StatusOK, toGroupsRes(groups, withRules))
}

// apiPutGroups
//
//	@Summary		Обновить список групп
//	@Description	Обновляет список групп
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Param			json	body		types.GroupsReq	true	"Тело запроса"
//	@Success		200		{object}	types.GroupsRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups [put]
func (a *App) apiPutGroups(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.GroupsReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Groups == nil {
		writeError(w, http.StatusBadRequest, "no groups in request")
		return
	}

	for _, groupWrapper := range a.groups {
		_ = groupWrapper.Disable()
	}

	newGroups := make([]*models.Group, 0, len(*req.Groups))
	for _, gReq := range *req.Groups {
		var existing *models.Group
		if gReq.ID != nil {
			for _, groupWrapper := range a.groups {
				if groupWrapper.Group.ID == *gReq.ID {
					existing = groupWrapper.Group
					break
				}
			}
		}
		group, err := fromGroupReq(gReq, existing)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		newGroups = append(newGroups, group)
	}

	a.groups = a.groups[:0]
	for _, g := range newGroups {
		if err := a.AddGroup(g); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJson(w, http.StatusOK, toGroupsRes(newGroups, true))
}

// apiCreateGroup
//
//	@Summary		Создать группу
//	@Description	Создает группу
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Param			json	body		types.GroupReq	true	"Тело запроса"
//	@Success		200		{object}	types.GroupRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups [post]
func (a *App) apiCreateGroup(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.GroupReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	group, err := fromGroupReq(req, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.AddGroup(group); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJson(w, http.StatusOK, toGroupRes(group, true))
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

// apiPutGroup
//
//	@Summary		Обновить группу
//	@Description	Обновляет запрошенную группу
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			json	body		types.GroupReq	true	"Тело запроса"
//	@Success		200		{object}	types.GroupRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID} [put]
func (a *App) apiPutGroup(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.GroupReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := a.groups[groupIdx]

	enabled := groupWrapper.enabled.Load()
	if enabled {
		if err := groupWrapper.Disable(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to disable group: %w", err).Error())
			return
		}
	}

	updatedGroup, err := fromGroupReq(req, groupWrapper.Group)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if enabled {
		if err := groupWrapper.Enable(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to enable group: %w", err).Error())
			return
		}
		if err := groupWrapper.Sync(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to sync group: %w", err).Error())
			return
		}
	}

	writeJson(w, http.StatusOK, toGroupRes(updatedGroup, true))
}

// apiDeleteGroup
//
//	@Summary		Удалить группу
//	@Description	Удаляет запрошенную группу
//	@Tags			groups
//	@Produce		json
//	@Param			groupID	path	string	true	"ID группы"
//	@Success		200
//	@Failure		404	{object}	types.ErrorRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID} [delete]
func (a *App) apiDeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := a.groups[groupIdx]
	if groupWrapper.enabled.Load() {
		if err := groupWrapper.Disable(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to disable group: %w", err).Error())
			return
		}
	}
	a.groups = append(a.groups[:groupIdx], a.groups[groupIdx+1:]...)
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

// apiPutRules
//
//	@Summary		Обновить список правил
//	@Description	Обновляет список правил
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			json	body		types.RulesRes	true	"Тело запроса"
//	@Success		200		{object}	types.RulesRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules [put]
func (a *App) apiPutRules(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.RulesReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Rules == nil {
		writeError(w, http.StatusBadRequest, "no rules in request")
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := a.groups[groupIdx]
	enabled := groupWrapper.enabled.Load()

	newRules := make([]*models.Rule, len(*req.Rules))
	for i, ruleReq := range *req.Rules {
		id := types.RandomID()
		if ruleReq.ID != nil {
			found := false
			for _, rule := range groupWrapper.Group.Rules {
				if rule.ID == *ruleReq.ID {
					id = *ruleReq.ID
					found = true
					break
				}
			}
			if !found {
				writeError(w, http.StatusNotFound, "rule not found")
				return
			}
		}
		newRules[i] = &models.Rule{
			ID:     id,
			Name:   ruleReq.Name,
			Type:   ruleReq.Type,
			Rule:   ruleReq.Rule,
			Enable: ruleReq.Enable,
		}
	}
	groupWrapper.Group.Rules = newRules

	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to sync group: %w", err).Error())
			return
		}
	}
	writeJson(w, http.StatusOK, toRulesRes(newRules))
}

// apiCreateRule
//
//	@Summary		Создать правило
//	@Description	Создает правило
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			json	body		types.RuleReq	true	"Тело запроса"
//	@Success		200		{object}	types.RuleRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules [post]
func (a *App) apiCreateRule(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.RuleReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := a.groups[groupIdx]
	enabled := groupWrapper.enabled.Load()

	rule, err := fromRuleReq(req, groupWrapper.Group.Rules)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupWrapper.Group.Rules = append(groupWrapper.Group.Rules, rule)

	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to sync group: %w", err).Error())
			return
		}
	}
	writeJson(w, http.StatusOK, toRuleRes(rule))
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

// apiPutRule
//
//	@Summary		Обновить правило
//	@Description	Обновляет запрошенное правило
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			ruleID	path		string			true	"ID правила"
//	@Param			json	body		types.RuleReq	true	"Тело запроса"
//	@Success		200		{object}	types.RuleRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules/{ruleID} [put]
func (a *App) apiPutRule(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.RuleReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := a.groups[groupIdx]
	enabled := groupWrapper.enabled.Load()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	rule := groupWrapper.Group.Rules[ruleIdx]

	rule.Name = req.Name
	rule.Type = req.Type
	rule.Rule = req.Rule
	rule.Enable = req.Enable

	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to sync group: %w", err).Error())
			return
		}
	}
	writeJson(w, http.StatusOK, toRuleRes(rule))
}

// apiDeleteRule
//
//	@Summary		Удалить правило
//	@Description	Удаляет запрошенное правило
//	@Tags			rules
//	@Produce		json
//	@Param			groupID	path	string	true	"ID группы"
//	@Param			ruleID	path	string	true	"ID правила"
//	@Success		200
//	@Failure		404	{object}	types.ErrorRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules/{ruleID} [delete]
func (a *App) apiDeleteRule(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := a.groups[groupIdx]
	enabled := groupWrapper.enabled.Load()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	groupWrapper.Group.Rules = append(groupWrapper.Group.Rules[:ruleIdx], groupWrapper.Group.Rules[ruleIdx+1:]...)

	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to sync group: %v", err).Error())
			return
		}
	}
}

// --- Маршрутизация ---

func (a *App) apiHandler(r chi.Router) {
	r.Route("/v1", func(r chi.Router) {
		r.Route("/groups", func(r chi.Router) {
			r.Get("/", a.apiGetGroups)
			r.Put("/", a.apiPutGroups)
			r.Post("/", a.apiCreateGroup)
			r.Route("/{groupID}", func(r chi.Router) {
				r.Use(func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						groupID := chi.URLParam(r, "groupID")
						id, err := types.ParseID(groupID)
						if err != nil {
							writeError(w, http.StatusBadRequest, "invalid group id")
							return
						}
						for i, group := range a.groups {
							if group.ID == id {
								r.Header.Set("groupIdx", strconv.Itoa(i))
								next.ServeHTTP(w, r)
								return
							}
						}
						writeError(w, http.StatusNotFound, "group not exist")
					})
				})
				r.Get("/", a.apiGetGroup)
				r.Put("/", a.apiPutGroup)
				r.Delete("/", a.apiDeleteGroup)
				r.Route("/rules", func(r chi.Router) {
					r.Get("/", a.apiGetRules)
					r.Put("/", a.apiPutRules)
					r.Post("/", a.apiCreateRule)
					r.Route("/{ruleID}", func(r chi.Router) {
						r.Use(func(next http.Handler) http.Handler {
							return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								ruleID := chi.URLParam(r, "ruleID")
								id, err := types.ParseID(ruleID)
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
							})
						})
						r.Get("/", a.apiGetRule)
						r.Put("/", a.apiPutRule)
						r.Delete("/", a.apiDeleteRule)
					})
				})
			})
		})
		r.Route("/system", func(r chi.Router) {
			r.Get("/interfaces", a.apiListInterfaces)
			r.Route("/config", func(r chi.Router) {
				r.Post("/save", a.apiSaveConfig)
			})
			r.Route("/hooks", func(r chi.Router) {
				r.Post("/netfilterd", a.apiNetfilterDHook)
			})
		})
	})
}
