package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/satyamsi/migrate/importyaml"
	"github.com/satyamsi/migrate/rulesetpolicies"
	"go.aporeto.io/elemental"
	"go.aporeto.io/gaia"
)

func o2str(obj interface{}) (string, error) {

	var prettyJSON bytes.Buffer

	b, err := elemental.Encode(elemental.EncodingTypeJSON, obj)
	if err != nil {
		return "", err
	}
	err = json.Indent(&prettyJSON, b, "", "\t")
	if err != nil {
		return "", err
	}
	return prettyJSON.String(), err
}

func getEnterPress() {
	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func readYAML(filename string, verbose bool) (enl gaia.ExternalNetworksList, npl gaia.NetworkAccessPoliciesList) {

	enl = gaia.ExternalNetworksList{}
	npl = gaia.NetworkAccessPoliciesList{}

	// Import external networks and network policies
	if err := importyaml.ImportFromFile(filename, &enl, &npl); err != nil {
		panic(err)
	}

	if verbose {
		fmt.Printf("Imported %d External network objects:\n", len(enl))
		s, err := o2str(enl)
		if err == nil {
			fmt.Println(s)
		}

		getEnterPress()

		fmt.Printf("Imported %d Network policy objects:\n", len(npl))
		s, err = o2str(npl)
		if err == nil {
			fmt.Println(s)
		}

		getEnterPress()
	}

	return
}

func main() {

	verbose := false
	enl, npl := readYAML("./input.yaml", verbose)

	orl := gaia.NetworkRuleSetPoliciesList{}
	enmap := map[string]*gaia.ExternalNetwork{}
	// Actual conversion
	for _, np := range npl {

		fmt.Println("\n\n\nInput Network Policy:")
		s, err := o2str(np)
		if err == nil {
			fmt.Println(s)
		}

		rsl, netl := rulesetpolicies.ConvertToNetworkRuleSetPolicies(np, enl)

		fmt.Println("Output Ruleset Policy:")

		s, err = o2str(rsl)
		if err == nil {
			fmt.Println(s)
		}

		orl = append(orl, rsl...)

		if len(netl) != 0 {

			fmt.Println("Output External Networks:")

			s, err = o2str(netl)
			if err == nil {
				fmt.Println(s)
			}

			for _, net := range netl {
				enmap[net.Name] = net
			}
		}

		if verbose {
			getEnterPress()
		}
	}

	if verbose {
		getEnterPress()

		fmt.Println("Consolidated Ruleset Policies:")
		s, err := o2str(orl)
		if err == nil {
			fmt.Println(s)
		}

		fmt.Println("Consolidated External Networks:")
		for net := range enmap {
			s, err = o2str(net)
			if err == nil {
				fmt.Println(s)
			}
		}
	}
}
