package magitrickle

import (
	"encoding/json"
	"fmt"
	"net/http"

	"magitrickle/api/types"
	"magitrickle/models"
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

func readJson[T any](r *http.Request) (T, error) {
	var req T
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		err = fmt.Errorf("failed to parse request: %w", err)
	}
	return req, err
}

// fromGroupReq конвертирует GroupReq в Group.
func fromGroupReq(req types.GroupReq, existingGroup *models.Group) (*models.Group, error) {
	var group *models.Group
	if existingGroup == nil {
		group = &models.Group{
			ID: types.RandomID(),
		}
	} else {
		group = existingGroup
	}
	if req.ID != nil {
		if existingGroup != nil && group.ID != *req.ID {
			return nil, fmt.Errorf("group ID mismatch")
		}
		if existingGroup == nil {
			group.ID = *req.ID
		}
	}
	group.Name = req.Name
	if !colorRegExp.MatchString(req.Color) {
		req.Color = "#ffffff"
	}
	group.Color = req.Color
	group.Interface = req.Interface
	group.FixProtect = req.FixProtect

	if req.Rules != nil {
		newRules := make([]*models.Rule, len(*req.Rules))
		for i, ruleReq := range *req.Rules {
			r, err := fromRuleReq(ruleReq, group.Rules)
			if err != nil {
				return nil, err
			}
			newRules[i] = r
		}
		group.Rules = newRules
	}
	return group, nil
}

// fromRuleReq конвертирует RuleReq в Rule.
func fromRuleReq(ruleReq types.RuleReq, existingRules []*models.Rule) (*models.Rule, error) {
	var rule *models.Rule
	if ruleReq.ID != nil {
		for _, r := range existingRules {
			if r.ID == *ruleReq.ID {
				rule = r
				break
			}
		}
	}
	if rule == nil {
		rule = &models.Rule{
			ID: types.RandomID(),
		}
	}
	rule.Name = ruleReq.Name
	rule.Type = ruleReq.Type
	rule.Rule = ruleReq.Rule
	rule.Enable = ruleReq.Enable
	return rule, nil
}

func toGroupsRes(groups []*models.Group, withRules bool) types.GroupsRes {
	groupResList := make([]types.GroupRes, len(groups))
	for i, group := range groups {
		groupResList[i] = toGroupRes(group, withRules)
	}
	return types.GroupsRes{Groups: &groupResList}
}

func toGroupRes(group *models.Group, withRules bool) types.GroupRes {
	groupRes := types.GroupRes{
		ID:         group.ID,
		Name:       group.Name,
		Color:      group.Color,
		Interface:  group.Interface,
		FixProtect: group.FixProtect,
	}
	if withRules {
		groupRes.RulesRes = toRulesRes(group.Rules)
	}
	return groupRes
}

func toRulesRes(rules []*models.Rule) types.RulesRes {
	ruleResList := make([]types.RuleRes, len(rules))
	for i, rule := range rules {
		ruleResList[i] = toRuleRes(rule)
	}
	return types.RulesRes{Rules: &ruleResList}
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
