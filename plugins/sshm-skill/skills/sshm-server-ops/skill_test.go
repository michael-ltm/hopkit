package sshmserverops

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func skillDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate skill_test.go")
	}
	return filepath.Dir(filename)
}

func readSkillFile(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(skillDir(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}

func TestCoreSkillBudget(t *testing.T) {
	core := readSkillFile(t, "SKILL.md")
	if words := len(strings.Fields(core)); words > 500 {
		t.Fatalf("SKILL.md has %d words; want at most 500", words)
	}
}

func TestCommonProjectBuildContextBudget(t *testing.T) {
	core := readSkillFile(t, "SKILL.md")
	workflow := readSkillFile(t, "project-workflows.md")
	if words := len(strings.Fields(core)) + len(strings.Fields(workflow)); words > 1150 {
		t.Fatalf("common project-build context has %d words; want at most 1150", words)
	}
	if bytes := len(core) + len(workflow); bytes > 8000 {
		t.Fatalf("common project-build context has %d bytes; want at most 8000", bytes)
	}
}

func TestCoreSkillRequiredGuidance(t *testing.T) {
	core := readSkillFile(t, "SKILL.md")
	for _, phrase := range []string{
		"find_servers",
		"list_projects",
		"get_project",
		"upsert_project",
		"exec_project",
		"do not retry the same failed mutation blindly",
		"changed host key",
	} {
		if !strings.Contains(core, phrase) {
			t.Errorf("SKILL.md does not contain %q", phrase)
		}
	}
}

func TestCoreSkillDefaultsToLineEfficientPlans(t *testing.T) {
	core := strings.Join(strings.Fields(readSkillFile(t, "SKILL.md")), " ")
	for _, phrase := range []string{"one short line per call", "one failure line", "one completion line"} {
		if !strings.Contains(core, phrase) {
			t.Errorf("SKILL.md does not contain compact plan rule %q", phrase)
		}
	}
}

func TestProjectLookupAvoidsRedundantList(t *testing.T) {
	core := strings.Join(strings.Fields(readSkillFile(t, "SKILL.md")), " ")
	workflow := strings.Join(strings.Fields(readSkillFile(t, "project-workflows.md")), " ")
	for _, phrase := range []string{"call `get_project` directly", "`list_projects` only", "do not call `list_projects` again"} {
		if !strings.Contains(core, phrase) {
			t.Errorf("SKILL.md does not contain profile lookup rule %q", phrase)
		}
	}
	if !strings.Contains(workflow, "core profile lookup rule") {
		t.Error("project-workflows.md does not reuse the core profile lookup rule")
	}
}

func TestCoreConditionalReferencesExist(t *testing.T) {
	core := readSkillFile(t, "SKILL.md")
	sectionStart := strings.Index(core, "## Conditional references")
	if sectionStart < 0 {
		t.Fatal("SKILL.md does not contain a Conditional references section")
	}

	linkPattern := regexp.MustCompile(`\[[^]]+\]\(([^)#?]+\.md)\)`)
	links := linkPattern.FindAllStringSubmatch(core[sectionStart:], -1)
	if len(links) < 5 {
		t.Fatalf("SKILL.md Conditional references contains %d documentation links; want at least 5", len(links))
	}

	seen := make(map[string]bool, len(links))
	for _, link := range links {
		reference := filepath.Clean(filepath.FromSlash(link[1]))
		if filepath.IsAbs(reference) || reference == ".." || strings.HasPrefix(reference, ".."+string(filepath.Separator)) {
			t.Errorf("conditional reference escapes the skill directory: %q", link[1])
			continue
		}
		if seen[reference] {
			t.Errorf("duplicate conditional reference %q", link[1])
			continue
		}
		seen[reference] = true
		if _, err := os.Stat(filepath.Join(skillDir(t), reference)); err != nil {
			t.Errorf("conditional reference %s: %v", link[1], err)
		}
	}
}

func TestReverseWorkflowRoutesToolsAndProtectsLabs(t *testing.T) {
	workflow := strings.Join(strings.Fields(readSkillFile(t, "reverse-workflows.md")), " ")
	for _, phrase := range []string{
		"jadx-analyze",
		"ida-export",
		"dynamic-reverse",
		"find_servers",
		"disposable lab/VM",
		"never a production server",
		"live `doctor`/capability output",
		"unique session directory",
		"target and tool SHA-256",
	} {
		if !strings.Contains(workflow, phrase) {
			t.Errorf("reverse-workflows.md does not contain %q", phrase)
		}
	}
}

func requirePhrasesInOrder(t *testing.T, contents string, phrases ...string) {
	t.Helper()
	contents = strings.Join(strings.Fields(contents), " ")
	start := 0
	for _, phrase := range phrases {
		phrase = strings.Join(strings.Fields(phrase), " ")
		offset := strings.Index(contents[start:], phrase)
		if offset < 0 {
			t.Fatalf("missing ordered workflow phrase %q after byte %d", phrase, start)
		}
		start += offset + len(phrase)
	}
}

func TestProjectWorkflowPreservesVerifiedBuildContract(t *testing.T) {
	workflow := readSkillFile(t, "project-workflows.md")
	normalizedWorkflow := strings.Join(strings.Fields(workflow), " ")

	if count := strings.Count(workflow, "check_ssh"); count != 1 {
		t.Errorf("project workflow mentions check_ssh %d times; want exactly once", count)
	}
	requirePhrasesInOrder(t, workflow,
		"Resolve once using the core profile lookup rule",
		"Run exactly one `check_ssh(mode=exec)`",
		"print the resolved workspace path",
		"verify expected project markers",
		"record the source revision or source archive SHA-256",
		"record the build start time",
		"pre-build artifact state and digest",
		"`verify_command` or the exact user-requested verification command",
		"pre-build verification only",
		"Run the configured `build_command`",
		"Validate the candidate artifact",
		"promote, copy, or move it to the canonical `artifact_path`",
		"modification time is after the recorded build start",
		"non-zero size",
		"SHA-256",
		"independent, side-effect-free artifact smoke command",
		"exact file under `local_artifact_dir`",
		"`artifact_path` basename",
	)

	for _, phrase := range []string{
		"non-detached `exec_project`",
		"`detach=false`",
		"from the outset",
		"realistic long `timeout_seconds` (or `0`)",
		"redirect stdout and stderr explicitly",
		"known log file under configured `remote_runs`",
		"`tail_logs platform=windows`",
		"transport or timeout",
		"PID",
		"process evidence",
		"Do not immediately relaunch",
	} {
		if !strings.Contains(normalizedWorkflow, phrase) {
			t.Errorf("project workflow does not contain Windows build contract phrase %q", phrase)
		}
	}

	lowerWorkflow := strings.ToLower(normalizedWorkflow)
	for _, forbidden := range []string{"fall back", "fallback"} {
		if strings.Contains(lowerWorkflow, forbidden) {
			t.Errorf("project workflow must not recommend detached-first fallback behavior containing %q", forbidden)
		}
	}
}

func TestProjectWorkflowRequiresCompactReporting(t *testing.T) {
	workflow := strings.Join(strings.Fields(readSkillFile(t, "project-workflows.md")), " ")
	for _, phrase := range []string{
		"one compact evidence table",
		"Do not narrate successful steps",
		"quote full logs",
	} {
		if !strings.Contains(workflow, phrase) {
			t.Errorf("project workflow does not contain compact reporting guidance %q", phrase)
		}
	}
}
