// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package inventory_test

import (
	"strings"
	"testing"

	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
)

func TestParseProfiles(t *testing.T) {
	csv := `node_id,display_name,environment,role,owner,location,labels
node-db,Payments DB,production,db,DBA team,seoul-dc,compliance=pci;tier=1
# comment rows are ignored
node-web,Payments Web,dev,web,Platform team,,
`
	profs, err := inventory.ParseProfiles(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 2 {
		t.Fatalf("%d profiles (want 2)", len(profs))
	}
	db := profs[0]
	if db.GetNodeId() != "node-db" || db.GetDisplayName() != "Payments DB" || db.GetRole() != "db" {
		t.Errorf("db fields: %+v", db)
	}
	if db.GetEnvironment() != inventoryv1.Environment_ENVIRONMENT_PRODUCTION {
		t.Errorf("environment: %v", db.GetEnvironment())
	}
	if db.GetLabels()["compliance"] != "pci" || db.GetLabels()["tier"] != "1" {
		t.Errorf("labels: %v", db.GetLabels())
	}
	if db.GetSource() != inventoryv1.ProfileSource_PROFILE_SOURCE_CMDB {
		t.Errorf("source: %v", db.GetSource())
	}
	if profs[1].GetEnvironment() != inventoryv1.Environment_ENVIRONMENT_DEVELOPMENT {
		t.Errorf("the dev alias did not parse: %v", profs[1].GetEnvironment())
	}
}
