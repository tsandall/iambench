package iambench

import (
	"strconv"
)

type Input struct {
	// Resource is the resource that access is requested to.
	Resource string `json:"resource"`

	// Action is the action that is requested on the resource.
	Action string `json:"action"`

	// Subject is the subject that is requesting access.
	Subject string `json:"subject"`

	// Context is the request's environmental context.
	Context map[string]interface{} `json:"context"`
}

type Policy struct {
	// ID is the unique identifier of the ORY Access Policy. It is used to query, update, and remove the ORY Access Policy.
	ID string `json:"id"`

	// Description is an optional, human-readable description.
	Description string `json:"description"`

	// Subjects is an array representing all the subjects this ORY Access Policy applies to.
	Subjects []string `json:"subjects"`

	// Resources is an array representing all the resources this ORY Access Policy applies to.
	Resources []string `json:"resources"`

	// Actions is an array representing all the actions this ORY Access Policy applies to.
	Actions []string `json:"actions"`

	// Effect is the effect of this ORY Access Policy. It can be "allow" or "deny".
	Effect string `json:"effect"`

	// Conditions represents a keyed object of conditions under which this ORY Access Policy is active.
	Conditions map[string]interface{} `json:"conditions"`
}

const ExactPolicy = `package ory.exact

import data.store.ory.exact as store
import input as request

default allow = false

allow {
	any_allow
	not any_deny
}

any_allow {
	effect_matches[[acp_id, "allow"]]
}

any_deny {
	effect_matches[[acp_id, "deny"]]
}

effect_matches[[acp_id, effect]] {
	effect := store.policies[acp_id].effect
	action_matches[acp_id]
	subject_matches[acp_id]
	resource_matches[acp_id]
	condition_matches[acp_id]
}

action_matches[acp_id] {
	store.policies[acp_id].actions[_] == request.action
}

resource_matches[acp_id] {
	store.policies[acp_id].resources[_] == request.resource
}

subject_matches[acp_id] {
	store.policies[acp_id].subjects[_] == request.subject
}

subject_matches[acp_id] {
	store.policies[acp_id].subjects[_] == store.roles[role_id].id
	store.roles[role_id].members[_] = request.subject
}

condition_matches[acp_id] {
	store.policies[acp_id] = _
	not any_conditions_fail[acp_id]
}

any_conditions_fail[acp_id] {
	condition := store.policies[acp_id].conditions[key]
	false
	#not data.ory.condition.eval_condition(condition.type, request, condition.options, key)
}`

const GlobPolicy = `package ory.glob

import data.store.ory.glob as store
import input as request

default allow = false

allow {
    any_allow
    not any_deny
}

any_allow {
	effect_matches[[acp_id, "allow"]]
}

any_deny {
	effect_matches[[acp_id, "deny"]]
}

effect_matches[[acp_id, effect]] {
	effect := store.policies[acp_id].effect
    action_matches[acp_id]
	subject_matches[acp_id]
    resource_matches[acp_id]
}

action_matches[acp_id] {
    matchfn(store.policies[acp_id].actions[_], request.action)
}

resource_matches[acp_id] {
	matchfn(store.policies[acp_id].resources[_], request.resource)
}

subject_matches[acp_id] {
	matchfn(store.policies[acp_id].subjects[_], request.subject)
}

subject_matches[acp_id] {
	store.roles[role_id].members[_] = request.subject
	matchfn(store.policies[acp_id].subjects[_], store.roles[role_id].id)
}

condition_matches[acp_id] {
	store.policies[acp_id] = _
	not any_conditions_fail[acp_id]
}

any_conditions_fail[acp_id] {
	condition := store.policies[acp_id].conditions[key]
	false
	#not data.ory.condition.eval_condition(condition.type, request, condition.options, key)
}

matchfn(pattern, match) {
    glob.match(pattern, [":"], match)
}`

func CreateExactACPs(amount int) map[string]interface{} {

	policies := make([]*Policy, amount)

	for i := 0; i < amount; i++ {
		id := strconv.Itoa(i)
		policies[i] = &Policy{
			ID:       id,
			Subjects: []string{"tenant:acmecorp:user:user.name@domain.com"},
			Resources: []string{
				"tenant:acmecorp:thing" + id + ":resource-1111-2222-3333-4444",
				"tenant:acmecorp:foo" + id + ":resource-1111-2222-3333-4444",
				"tenant:acmecorp:bar" + id + ":resource-1111-2222-3333-4444",
				"tenant:acmecorp:baz" + id + ":resource-1111-2222-3333-4444",
				"tenant:acmecorp:boo" + id + ":resource-1111-2222-3333-4444",
				"tenant:acmecorp:bam" + id + ":resource-1111-2222-3333-4444",
				"tenant:acmecorp:bag" + id + ":resource-1111-2222-3333-4444",
				"tenant:acmecorp:bad" + id + ":resource-1111-2222-3333-4444",
			},
			Actions: []string{"check"},
			Effect:  "allow",
		}
	}

	return map[string]interface{}{
		"store": map[string]interface{}{
			"ory": map[string]interface{}{
				"exact": &struct {
					Policies []*Policy `json:"policies"`
					Roles    []string  `json:"roles"`
				}{
					Policies: policies,
					Roles:    []string{},
				},
			},
		},
	}
}

func CreateGlobACPs(amount int) map[string]interface{} {

	policies := make([]*Policy, amount)

	for i := 0; i < amount; i++ {
		id := strconv.Itoa(i)
		policies[i] = &Policy{
			ID:       id,
			Subjects: []string{"tenant:*:user:*"},
			Resources: []string{
				"tenant:*:thing" + id + ":*",
				"tenant:*:foo" + id + ":*",
				"tenant:*:bar" + id + ":*",
				"tenant:*:baz" + id + ":*",
				"tenant:*:boo" + id + ":*",
				"tenant:*:bam" + id + ":*",
				"tenant:*:bag" + id + ":*",
				"tenant:*:bad" + id + ":*",
			},
			Actions: []string{"check"},
			Effect:  "allow",
		}
	}

	return map[string]interface{}{
		"store": map[string]interface{}{
			"ory": map[string]interface{}{
				"exact": &struct {
					Policies []*Policy `json:"policies"`
					Roles    []string  `json:"roles"`
				}{
					Policies: policies,
					Roles:    []string{},
				},
			},
		},
	}
}
