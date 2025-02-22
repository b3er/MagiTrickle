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
//	@Router			/v1/system/hooks/netfilterd [post]
func (a *App) apiNetfilterDHook(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.NetfilterDHookReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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

// apiListInterfaces
//
//	@Summary		Получить список интерфейсов
//	@Description	Возвращает список интерфейсов
//	@Tags			config
//	@Produce		json
//	@Success		200 {object}    types.InterfacesRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/v1/system/interfaces [get]
func (a *App) apiListInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces, err := a.ListInterfaces()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to get interfaces: %w", err).Error())
		return
	}

	interfacesRes := make([]types.InterfaceRes, len(interfaces))
	for idx, iface := range interfaces {
		interfacesRes[idx] = types.InterfaceRes{ID: iface.Name}
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
//	@Router			/v1/system/config/save [post]
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
//	@Router			/v1/groups [get]
func (a *App) apiGetGroups(w http.ResponseWriter, r *http.Request) {
	withRules := r.URL.Query().Get("with_rules") == "true"
	groups := make([]*models.Group, len(a.groups))
	for idx, group := range a.groups {
		groups[idx] = group.Group
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
//	@Router			/v1/groups [put]
func (a *App) apiPutGroups(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.GroupsReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
	}

	if req.Groups == nil {
		return
	}

	for _, group := range a.groups {
		_ = group.Disable()
	}

	groups := make([]*models.Group, len(*req.Groups))
	for idx, group := range *req.Groups {
		groupId := types.RandomID()
		groupIdx := -1
		if group.ID != nil {
			var ok bool
			for idx, aGroup := range a.groups {
				if aGroup.ID == *group.ID {
					ok = true
					groupId = *group.ID
					groupIdx = idx
					break
				}
			}
			if !ok {
				writeError(w, http.StatusNotFound, fmt.Errorf("group not found").Error())
				return
			}
		}

		var rules []*models.Rule
		if group.Rules != nil {
			rules = make([]*models.Rule, len(*group.Rules))
			for idx, rule := range *group.Rules {
				id := types.RandomID()
				if rule.ID != nil {
					if groupIdx == -1 {
						writeError(w, http.StatusNotFound, fmt.Errorf("rule not found").Error())
						return
					}
					group := a.groups[groupIdx]
					var ok bool
					for _, ruleModel := range group.Rules {
						if ruleModel.ID == *rule.ID {
							ok = true
							id = *rule.ID
							break
						}
					}
					if !ok {
						writeError(w, http.StatusNotFound, fmt.Errorf("rule not found").Error())
						return
					}
					id = *rule.ID
				}
				rules[idx] = &models.Rule{
					ID:     id,
					Name:   rule.Name,
					Type:   rule.Type,
					Rule:   rule.Rule,
					Enable: rule.Enable,
				}
			}
		}

		groups[idx] = &models.Group{
			ID:         groupId,
			Name:       group.Name,
			Interface:  group.Interface,
			FixProtect: group.FixProtect,
			Rules:      rules,
		}
	}

	a.groups = a.groups[:0]
	for _, group := range groups {
		err = a.AddGroup(group)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
	}
	writeJson(w, http.StatusOK, toGroupsRes(groups, true))
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
//	@Router			/v1/groups [post]
func (a *App) apiCreateGroup(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.GroupReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
	}

	var rules []*models.Rule
	if req.Rules != nil {
		rules = make([]*models.Rule, len(*req.Rules))
		for idx, rule := range *req.Rules {
			rules[idx] = &models.Rule{
				ID:     types.RandomID(),
				Name:   rule.Name,
				Type:   rule.Type,
				Rule:   rule.Rule,
				Enable: rule.Enable,
			}
		}
	}

	group := &models.Group{
		ID:         types.RandomID(),
		Name:       req.Name,
		Interface:  req.Interface,
		FixProtect: req.FixProtect,
		Rules:      rules,
	}
	err = a.AddGroup(group)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
//	@Router			/v1/groups/{groupID} [get]
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
//	@Router			/v1/groups/{groupID} [put]
func (a *App) apiPutGroup(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.GroupReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
	}

	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	group := a.groups[groupIdx]
	enabled := group.enabled.Load()
	if enabled {
		err = group.Disable()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to disable group: %w", err).Error())
			return
		}
	}

	var rules []*models.Rule
	if req.Rules != nil {
		rules = make([]*models.Rule, len(*req.Rules))
		for idx, rule := range *req.Rules {
			id := types.RandomID()
			if rule.ID != nil {
				var ok bool
				for _, ruleModel := range group.Rules {
					if ruleModel.ID == *rule.ID {
						ok = true
						id = *rule.ID
						break
					}
				}
				if !ok {
					writeError(w, http.StatusNotFound, fmt.Errorf("rule not found").Error())
					return
				}
			}
			rules[idx] = &models.Rule{
				ID:     id,
				Name:   rule.Name,
				Type:   rule.Type,
				Rule:   rule.Rule,
				Enable: rule.Enable,
			}
		}
		group.Rules = rules
	}
	group.Name = req.Name
	group.Interface = req.Interface
	group.FixProtect = req.FixProtect

	if enabled {
		err = group.Enable()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to enable group: %w", err).Error())
			return
		}
		err = group.Sync()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to sync group: %w", err).Error())
			return
		}
	}

	writeJson(w, http.StatusOK, toGroupRes(group.Group, true))
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
//	@Router			/v1/groups/{groupID} [delete]
func (a *App) apiDeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	group := a.groups[groupIdx]
	enabled := group.enabled.Load()
	if enabled {
		err := group.Disable()
		if err != nil {
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
//	@Router			/v1/groups/{groupID}/rules [get]
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
//	@Router			/v1/groups/{groupID}/rules [put]
func (a *App) apiPutRules(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.RulesReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
	}

	if req.Rules == nil {
		return
	}

	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	group := a.groups[groupIdx]
	enabled := group.enabled.Load()

	var rules []*models.Rule
	rules = make([]*models.Rule, len(*req.Rules))
	for idx, rule := range *req.Rules {
		id := types.RandomID()
		if rule.ID != nil {
			var ok bool
			for _, ruleModel := range group.Rules {
				if ruleModel.ID == *rule.ID {
					ok = true
					id = *rule.ID
					break
				}
			}
			if !ok {
				writeError(w, http.StatusNotFound, fmt.Errorf("rule not found").Error())
				return
			}
		}
		rules[idx] = &models.Rule{
			ID:     id,
			Name:   rule.Name,
			Type:   rule.Type,
			Rule:   rule.Rule,
			Enable: rule.Enable,
		}
	}
	group.Rules = rules

	if enabled {
		err = group.Sync()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to sync group: %w", err).Error())
			return
		}
	}

	writeJson(w, http.StatusOK, toRulesRes(rules))
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
//	@Router			/v1/groups/{groupID}/rules [post]
func (a *App) apiCreateRule(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.RuleReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
	}

	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	group := a.groups[groupIdx]
	enabled := group.enabled.Load()

	rule := &models.Rule{
		ID:     types.RandomID(),
		Name:   req.Name,
		Type:   req.Type,
		Rule:   req.Rule,
		Enable: req.Enable,
	}
	group.Rules = append(group.Rules, rule)

	if enabled {
		err = group.Sync()
		if err != nil {
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
//	@Router			/v1/groups/{groupID}/rules/{ruleID} [get]
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
//	@Router			/v1/groups/{groupID}/rules/{ruleID} [put]
func (a *App) apiPutRule(w http.ResponseWriter, r *http.Request) {
	req, err := readJson[types.RuleReq](r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
	}

	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	group := a.groups[groupIdx]
	enabled := group.enabled.Load()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	rule := group.Group.Rules[ruleIdx]

	rule.Name = req.Name
	rule.Type = req.Type
	rule.Rule = req.Rule
	rule.Enable = req.Enable

	if enabled {
		err = group.Sync()
		if err != nil {
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
//	@Router			/v1/groups/{groupID}/rules/{ruleID} [delete]
func (a *App) apiDeleteRule(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	group := a.groups[groupIdx]
	enabled := group.enabled.Load()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))

	group.Rules = append(group.Rules[:ruleIdx], group.Rules[ruleIdx+1:]...)

	if enabled {
		err := group.Sync()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to sync group: %v", err).Error())
			return
		}
	}
}

func (a *App) apiHandler(r chi.Router) {
	r.Route("/v1", func(r chi.Router) {
		r.Route("/groups", func(r chi.Router) {
			r.Get("/", a.apiGetGroups)
			r.Put("/", a.apiPutGroups)
			r.Post("/", a.apiCreateGroup)
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
				r.Put("/", a.apiPutGroup)
				r.Delete("/", a.apiDeleteGroup)
				r.Route("/rules", func(r chi.Router) {
					r.Get("/", a.apiGetRules)
					r.Put("/", a.apiPutRules)
					r.Post("/", a.apiCreateRule)
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
