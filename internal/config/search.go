package config

import (
	"sort"
	"strings"
	"unicode"
)

// ServerMatch is one intent-based inventory match. Score is only meaningful
// relative to other results from the same query.
type ServerMatch struct {
	Alias     string
	Server    *Server
	Score     int
	MatchedOn []string
}

type searchField struct {
	name   string
	value  string
	weight int
}

// SearchServers matches every query term across AI-safe discovery metadata. It
// deliberately excludes Notes, which are local/private operational text. All
// terms must match somewhere, which keeps AI lookups such as
// "windows dynamic-debug" precise even in large inventories.
func SearchServers(servers map[string]*Server, query string) []ServerMatch {
	terms := searchTerms(query)
	if len(terms) == 0 {
		return nil
	}

	matches := make([]ServerMatch, 0)
	for alias, server := range servers {
		if server == nil {
			continue
		}
		fields := []searchField{
			{name: "alias", value: alias, weight: 100},
			{name: "label", value: server.Label, weight: 80},
			{name: "description", value: server.Description, weight: 60},
			{name: "tags", value: strings.Join(server.Tags, " "), weight: 50},
			{name: "group", value: server.Group, weight: 40},
			{name: "user", value: server.User, weight: 20},
			{name: "host", value: server.Host, weight: 10},
		}

		normalized := make([]string, len(fields))
		for index, field := range fields {
			normalized[index] = normalizeSearchText(field.value)
		}

		score := 0
		matchedFields := map[string]bool{}
		allTermsMatched := true
		for _, term := range terms {
			termMatched := false
			for index, field := range fields {
				if normalized[index] == "" || !strings.Contains(normalized[index], term) {
					continue
				}
				termMatched = true
				score += field.weight
				matchedFields[field.name] = true
			}
			if !termMatched {
				allTermsMatched = false
				break
			}
		}
		if !allTermsMatched {
			continue
		}

		normalizedQuery := normalizeSearchText(query)
		if normalized[0] == normalizedQuery {
			score += 200
		}
		matchedOn := make([]string, 0, len(matchedFields))
		for _, field := range fields {
			if matchedFields[field.name] {
				matchedOn = append(matchedOn, field.name)
			}
		}
		matches = append(matches, ServerMatch{
			Alias: alias, Server: server, Score: score, MatchedOn: matchedOn,
		})
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		return matches[i].Alias < matches[j].Alias
	})
	return matches
}

func searchTerms(query string) []string {
	return strings.Fields(normalizeSearchText(query))
}

func normalizeSearchText(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Join(strings.FieldsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(",;|/\\:_()[]{}", r)
	}), " ")
}
