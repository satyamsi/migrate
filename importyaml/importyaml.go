package importyaml

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
	"go.aporeto.io/gaia"
	"golang.org/x/sync/errgroup"
)

// Import handles the creates requests for Import.
func Import(
	importReq *gaia.Import,
	enl *gaia.ExternalNetworksList,
	npl *gaia.NetworkAccessPoliciesList,
) error {

	var g errgroup.Group

	// We first deal with namespaces
	if data, ok := importReq.Data.Data[gaia.NamespaceIdentity.Category]; ok {

		if err := makeImportJobFunc(importReq.Data.Label, importReq.Mode, gaia.NamespaceIdentity.Category, data, enl, npl)(); err != nil {
			return err
		}

		// then we remove them from the map
		delete(importReq.Data.Data, gaia.NamespaceIdentity.Category)
	}

	// Then we import the rest
	for identity := range importReq.Data.Data {
		g.Go(makeImportJobFunc(importReq.Data.Label, importReq.Mode, identity, importReq.Data.Data[identity], enl, npl))
	}

	return g.Wait()
}

func makeImportJobFunc(
	label string,
	mode gaia.ImportModeValue,
	identity string,
	data []map[string]interface{},
	enl *gaia.ExternalNetworksList,
	npl *gaia.NetworkAccessPoliciesList,
) func() error {
	return func() (err error) {

		i := gaia.Manager().IdentityFromCategory(identity)
		if i.IsEmpty() {
			return fmt.Errorf("empty identity")
		}
		// Then we must decode objects one by one otherwise
		// nothing will call NewThing and the default values will
		// not be initialized.
		for _, item := range data {

			o := gaia.Manager().Identifiable(i)
			if o == nil {
				return fmt.Errorf("unable to get identifiable from identity: %s", i)
			}

			if err = mapstructure.Decode(item, &o); err != nil {
				return fmt.Errorf("bad item for '%s'", identity)
			}

			en, ok := o.(*gaia.ExternalNetwork)
			if ok {
				*enl = append(*enl, en)
			} else {
				np, ok := o.(*gaia.NetworkAccessPolicy)
				if ok {
					*npl = append(*npl, np)
				} else {
					fmt.Println("not sure")
				}
			}
		}

		return err
	}
}
