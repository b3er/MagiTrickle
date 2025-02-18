package magitrickle

import (
	"encoding/json"
	"net/http"

	"magitrickle/models"
	"magitrickle/pkg/magitrickle-api/types"
)

func writeJson(w http.ResponseWriter, httpCode int, data interface{}) {
	errJson, err := json.Marshal(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpCode)
	w.Write(errJson)
}

func writeError(w http.ResponseWriter, httpCode int, e string) {
	writeJson(w, httpCode, types.ErrorRes{Error: e})
}

func toGroupsRes(groups []*models.Group, withRules bool) types.GroupsRes {
	groupsRes := make([]types.GroupRes, len(groups))
	for idx, group := range groups {
		groupsRes[idx] = toGroupRes(group, withRules)
	}
	return types.GroupsRes{Groups: &groupsRes}
}

func toGroupRes(group *models.Group, withRules bool) types.GroupRes {
	groupRes := types.GroupRes{
		ID:         group.ID,
		Name:       group.Name,
		Interface:  group.Interface,
		FixProtect: group.FixProtect,
	}
	if withRules {
		groupRes.RulesRes = toRulesRes(group.Rules)
	}
	return groupRes
}

func toRulesRes(rules []*models.Rule) types.RulesRes {
	rulesRes := make([]types.RuleRes, len(rules))
	for idx, rule := range rules {
		rulesRes[idx] = toRuleRes(rule)
	}
	return types.RulesRes{Rules: &rulesRes}
}

func toRuleRes(rule *models.Rule) types.RuleRes {
	return types.RuleRes{
		ID:     rule.ID,
		Name:   rule.Name,
		Type:   rule.Type,
		Rule:   rule.Rule,
		Enable: rule.Enable,
	}
}
