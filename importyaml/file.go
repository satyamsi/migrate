package importyaml

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"go.aporeto.io/gaia"
	"sigs.k8s.io/yaml"
)

// ImportFromFile imports the data from a file. It uses the manipulator to write
// the data to the corresponding target.
func ImportFromFile(filename string, enl *gaia.ExternalNetworksList, npl *gaia.NetworkAccessPoliciesList) error {

	data, err := ioutil.ReadFile(filename) // #nosec
	if err != nil {
		return fmt.Errorf("file error: %s", err)
	}

	if data == nil {
		return fmt.Errorf("empty file")
	}

	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return err
	}

	exportData := gaia.NewExport()
	if err = json.Unmarshal(jsonData, &exportData); err != nil {
		return err
	}

	importData := gaia.NewImport()
	importData.Data = exportData
	importData.Mode = gaia.ImportModeImport

	return Import(importData, enl, npl)
}
