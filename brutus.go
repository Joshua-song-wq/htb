package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/elastic/go-grok"
	"github.com/elastic/go-grok/patterns"
)

func main() {
	g := grok.New()

	// use custom patterns
	patternDefinitions := map[string]string{
		// patterns can be nested
		"SESSION_ACTION":   "(New session|Session|Removed session)",
		"PAM_UNIX_SESSION": `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: %{DATA:type2}\(%{DATA}\:%{DATA:type3}\)\:%{GREEDYDATA} user %{USERNAME:username}(?:\(%{DATA}\=%{BASE10NUM:to_uid}\) by \(%{DATA}\=%{BASE10NUM:from_uid}\))?`,
		"SUDO_PREFIX":      `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: %{USERNAME:orig_username} : TTY=%{DATA:TTY} ; PWD=%{DATA:pwd} ; USER=%{USERNAME:username} ; COMMAND=%{DATA:command}$`,
		"INVALID":          `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: %{GREEDYDATA:result} %{USERNAME:username} from %{IPV4:srcIP} port %{BASE10NUM:port}(?: %{GREEDYDATA:method})?`,
		"PAM_UNIX_FAIL":    `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: %{GREEDYDATA:result}; logname=%{DATA:logname} uid=%{BASE10NUM:uid} euid=%{BASE10NUM:euid} tty=%{DATA:tty} ruser=%{DATA:ruser} rhost=%{IPV4:rhost}`,
		"BRUTE":            `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: %{GREEDYDATA:result} (?:from|by)? %{DATA:user_exist} %{USERNAME:username} %{IPV4:srcIP} port %{BASE10NUM:port}(?: \[%{GREEDYDATA:method}\])?`,
		"SESSION":          `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: %{SESSION_ACTION:session_action} %{BASE10NUM:session}%{GREEDYDATA}%{WORD:detail}`,
		"GROUP":            `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: (?:group added to %{DATA:file}:|new group:)? name=%{WORD:group_name}(?:, GID=%{BASE10NUM:gid})?`,
		"AUTHORIZED_KEYS":  `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: %{DATA:type2} %{DATA:file} %{USERNAME:username} %{WORD:hashmod}:%{DATA:hash} failed, status %{BASE10NUM:status}`,
		"SSHD_DROP":        `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: (error|drop|exited)%{GREEDYDATA:detail}`,
		"USER_MOD":         `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: %{WORD:method} '%{USERNAME:username}' to %{GREEDYDATA:group} '%{WORD:allowed}'`,
		"USER_ADD":         `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: new user: name=%{USERNAME:username}, UID=%{BASE10NUM:uid}, GID=%{BASE10NUM:gid}, home=%{DATA:home}, shell=%{DATA:shell}, from=%{DATA:from}`,
		"PASS_MOD":         `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: pam_unix\(passwd:%{DATA:new_pass}\): password changed for %{USERNAME:username}`,
		"CHFN":             `%{SYSLOGBASE2} %{DATA:host} %{DATA:type}(?:\[%{BASE10NUM:pid}\])?\: changed user '%{USERNAME:username}'`,
	}
	// load patterns
	g.AddPatterns(patterns.Syslog)
	g.AddPatterns(patternDefinitions)

	// collect sorted keys
	names := make([]string, 0, len(patternDefinitions))
	for name := range patternDefinitions {
		if name == "SESSION_ACTION" {
			continue // skip helper pattern
		}
		names = append(names, name)
	}
	sort.Strings(names)
	names = append(names, "ALL")

	// check CLI args
	if len(os.Args) != 2 {
		printUsage(names)
		return
	}

	choice, err := strconv.Atoi(os.Args[1])
	if err != nil || choice < 1 || choice > len(names) {
		printUsage(names)
		return
	}

	chosen := names[choice-1]

	// build final pattern
	var finalPattern string
	if chosen == "ALL" {
		for i, name := range names[:len(names)-1] {
			finalPattern += "%{" + name + "}"
			if i < len(names)-2 {
				finalPattern += "|"
			}
		}
	} else {
		finalPattern = "%{" + chosen + "}"
	}

	// compile
	err = g.Compile(finalPattern, true)
	if err != nil {
		panic(err)
	}

	// open log
	file, err := os.Open("auth.log")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// collect results
	var results []map[string]string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		res, err := g.ParseString(line)
		if err != nil {
			panic(err)
		}
		if len(res) > 0 {
			results = append(results, res)
		}
	}

	// marshal once at the end as a JSON array
	jsonData, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(jsonData))
}

func printUsage(names []string) {
	fmt.Println("Usage: go run main.go <number>")
	fmt.Println("\nAvailable patterns:")
	for i, name := range names {
		fmt.Printf("  %d) %s\n", i+1, name)
	}
}
