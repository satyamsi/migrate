package rulesetpolicies

import (
	"reflect"
	"testing"

	"go.aporeto.io/gaia"
)

func Test_convertToNetworkRuleAction(t *testing.T) {

	tests := []struct {
		name   string
		action gaia.NetworkAccessPolicyActionValue
		want   gaia.NetworkRuleActionValue
	}{
		{
			"allow",
			gaia.NetworkAccessPolicyActionAllow,
			gaia.NetworkRuleActionAllow,
		},
		{
			"reject",
			gaia.NetworkAccessPolicyActionReject,
			gaia.NetworkRuleActionReject,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertToNetworkRuleAction(tt.action)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertToNetworkRuleAction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getMatchingExternalNetworks(t *testing.T) {

	en1 := &gaia.ExternalNetwork{
		Name:           "en1",
		AssociatedTags: []string{"a"},
	}
	en2 := &gaia.ExternalNetwork{
		Name:           "en2",
		AssociatedTags: []string{"c"},
	}

	type args struct {
		objects [][]string
		extnets gaia.ExternalNetworksList
	}
	tests := []struct {
		name      string
		args      args
		wantMatch gaia.ExternalNetworksList
	}{
		{
			name: "basic match",
			args: args{
				objects: [][]string{
					{"a", "b"},
					{"c"},
				},
				extnets: gaia.ExternalNetworksList{
					en1,
					en2,
				},
			},
			wantMatch: gaia.ExternalNetworksList{
				en2,
			},
		},
		{
			name: "basic match all",
			args: args{
				objects: [][]string{
					{"a"},
					{"c"},
				},
				extnets: gaia.ExternalNetworksList{
					en1,
					en2,
				},
			},
			wantMatch: gaia.ExternalNetworksList{
				en1,
				en2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotMatch := getMatchingExternalNetworks(tt.args.objects, tt.args.extnets); !reflect.DeepEqual(gotMatch, tt.wantMatch) {
				t.Errorf("getMatchingExternalNetworks() = %v, want %v", gotMatch, tt.wantMatch)
			}
		})
	}
}

func Test_externalNetworksMatchTags(t *testing.T) {

	en1 := &gaia.ExternalNetwork{
		Name:           "en1",
		AssociatedTags: []string{"a", "b"},
	}

	type args struct {
		extnet *gaia.ExternalNetwork
		tags   []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "match basic",
			args: args{
				en1,
				[]string{"a", "b"},
			},
			want: true,
		},
		{
			name: "subset match basic",
			args: args{
				en1,
				[]string{"a"},
			},
			want: true,
		},
		{
			name: "superset match basic",
			args: args{
				en1,
				[]string{"a", "b", "c"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalNetworksMatchTags(tt.args.extnet, tt.args.tags); got != tt.want {
				t.Errorf("externalNetworksMatchTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvertToNetworkRuleSetPolicies(t *testing.T) {
	type args struct {
		netpol *gaia.NetworkAccessPolicy
		extnet gaia.ExternalNetworksList
	}
	tests := []struct {
		name              string
		args              args
		wantOutNetPolList gaia.NetworkRuleSetPoliciesList
		wantOutExtNetList gaia.ExternalNetworksList
	}{
		{
			name: "allow incoming identity network policy with no matching external networks",
			args: args{
				netpol: func() *gaia.NetworkAccessPolicy {
					netpol := gaia.NewNetworkAccessPolicy()
					netpol.Name = "name"
					netpol.Namespace = "namespace"
					netpol.ApplyPolicyMode = gaia.NetworkAccessPolicyApplyPolicyModeIncomingTraffic
					netpol.Action = gaia.NetworkAccessPolicyActionAllow
					netpol.Subject = [][]string{{"app=foo"}}
					netpol.Object = [][]string{{"app=bar"}}
					return netpol
				}(),
				extnet: gaia.ExternalNetworksList{},
			},
			wantOutNetPolList: gaia.NetworkRuleSetPoliciesList{
				{
					Name:      "name",
					Namespace: "namespace",
					Subject:   [][]string{{"app=bar"}}, // For Incoming traffic new subject is same as old object
					IncomingRules: []*gaia.NetworkRule{
						{
							Action: gaia.NetworkRuleActionAllow,
							Object: [][]string{{"app=foo"}}, // For Incoming traffic new object is same as old subject
						},
					},
				},
			},
			wantOutExtNetList: gaia.ExternalNetworksList{},
		},
		{
			name: "allow outgoing identity network policy with no matching external networks",
			args: args{
				netpol: func() *gaia.NetworkAccessPolicy {
					netpol := gaia.NewNetworkAccessPolicy()
					netpol.Name = "name"
					netpol.Namespace = "namespace"
					netpol.ApplyPolicyMode = gaia.NetworkAccessPolicyApplyPolicyModeOutgoingTraffic
					netpol.Action = gaia.NetworkAccessPolicyActionAllow
					netpol.Subject = [][]string{{"app=foo"}}
					netpol.Object = [][]string{{"app=bar"}}
					return netpol
				}(),
				extnet: gaia.ExternalNetworksList{},
			},
			wantOutNetPolList: gaia.NetworkRuleSetPoliciesList{
				{
					Name:      "name",
					Namespace: "namespace",
					Subject:   [][]string{{"app=foo"}}, // For Outgoing traffic new subject is same as old subject
					OutgoingRules: []*gaia.NetworkRule{
						{
							Action: gaia.NetworkRuleActionAllow,
							Object: [][]string{{"app=bar"}}, // For Outgoing traffic new object is same as old object
						},
					},
				},
			},
			wantOutExtNetList: gaia.ExternalNetworksList{},
		},
		{
			name: "allow bidirectional identity network policy with no matching external networks",
			args: args{
				netpol: func() *gaia.NetworkAccessPolicy {
					netpol := gaia.NewNetworkAccessPolicy()
					netpol.Name = "name"
					netpol.Namespace = "namespace"
					netpol.ApplyPolicyMode = gaia.NetworkAccessPolicyApplyPolicyModeBidirectional
					netpol.Action = gaia.NetworkAccessPolicyActionAllow
					netpol.Subject = [][]string{{"app=foo"}}
					netpol.Object = [][]string{{"app=bar"}}
					return netpol
				}(),
				extnet: gaia.ExternalNetworksList{},
			},
			wantOutNetPolList: gaia.NetworkRuleSetPoliciesList{
				{
					Name:      "name",
					Namespace: "namespace",
					Subject:   [][]string{{"app=bar"}}, // For Incoming traffic new subject is same as old object
					IncomingRules: []*gaia.NetworkRule{
						{
							Action: gaia.NetworkRuleActionAllow,
							Object: [][]string{{"app=foo"}}, // For Incoming traffic new object is same as old subject
						},
					},
				},
				{
					Name:      "name",
					Namespace: "namespace",
					Subject:   [][]string{{"app=foo"}}, // For Outgoing traffic new subject is same as old subject
					OutgoingRules: []*gaia.NetworkRule{
						{
							Action: gaia.NetworkRuleActionAllow,
							Object: [][]string{{"app=bar"}}, // For Outgoing traffic new object is same as old object
						},
					},
				},
			},
			wantOutExtNetList: gaia.ExternalNetworksList{},
		},
		{
			name: "allow incoming ACL network policy with external networks",
			args: args{
				netpol: func() *gaia.NetworkAccessPolicy {
					netpol := gaia.NewNetworkAccessPolicy()
					netpol.Name = "name"
					netpol.Namespace = "namespace"
					netpol.ApplyPolicyMode = gaia.NetworkAccessPolicyApplyPolicyModeIncomingTraffic
					netpol.Action = gaia.NetworkAccessPolicyActionAllow
					netpol.Subject = [][]string{{"app=foo"}}
					netpol.Object = [][]string{{"app=bar"}}
					return netpol
				}(),
				extnet: gaia.ExternalNetworksList{
					{
						Name:           "e1",
						AssociatedTags: []string{"app=foo"},
						Entries:        []string{"10.10.10.10/32"},
						ServicePorts:   []string{"tcp/80"},
					},
				},
			},
			wantOutNetPolList: gaia.NetworkRuleSetPoliciesList{
				{
					Name:      "name",
					Namespace: "namespace",
					Subject:   [][]string{{"app=bar"}}, // For Incoming traffic new subject is same as old object
					IncomingRules: []*gaia.NetworkRule{
						{
							Action:        gaia.NetworkRuleActionAllow,
							Object:        [][]string{{"app=foo", "$identity=externalnetwork", "$name=e1", "version=v2"}}, // For Incoming traffic new object is same as old subject
							ProtocolPorts: []string{"tcp/80"},                                                             // ProtocolPorts are moved here from external networks
						},
					},
				},
			},
			wantOutExtNetList: gaia.ExternalNetworksList{
				{
					Name:           "e1",
					AssociatedTags: []string{"app=foo", "version=v2"},
					Entries:        []string{"10.10.10.10/32"},
					ServicePorts:   []string{"tcp/80"},
				},
			},
		},
		{
			name: "allow outgoing ACL network policy with external networks",
			args: args{
				netpol: func() *gaia.NetworkAccessPolicy {
					netpol := gaia.NewNetworkAccessPolicy()
					netpol.Name = "name"
					netpol.Namespace = "namespace"
					netpol.ApplyPolicyMode = gaia.NetworkAccessPolicyApplyPolicyModeOutgoingTraffic
					netpol.Action = gaia.NetworkAccessPolicyActionAllow
					netpol.Subject = [][]string{{"app=foo"}}
					netpol.Object = [][]string{{"app=bar"}}
					return netpol
				}(),
				extnet: gaia.ExternalNetworksList{
					{
						Name:           "e1",
						AssociatedTags: []string{"app=bar"},
						Entries:        []string{"10.10.10.10/32"},
						ServicePorts:   []string{"tcp/80"},
					},
				},
			},
			wantOutNetPolList: gaia.NetworkRuleSetPoliciesList{
				{
					Name:      "name",
					Namespace: "namespace",
					Subject:   [][]string{{"app=foo"}},
					OutgoingRules: []*gaia.NetworkRule{
						{
							Action:        gaia.NetworkRuleActionAllow,
							Object:        [][]string{{"app=bar", "$identity=externalnetwork", "$name=e1", "version=v2"}},
							ProtocolPorts: []string{"tcp/80"},
						},
					},
				},
			},
			wantOutExtNetList: gaia.ExternalNetworksList{
				{
					AssociatedTags: []string{"app=bar", "version=v2"},
					Entries:        []string{"10.10.10.10/32"},
					ServicePorts:   []string{"tcp/80"},
				},
			},
		},
		{
			name: "allow outgoing ACL network policy with external networks (ports/protocol intersection)",
			args: args{
				netpol: func() *gaia.NetworkAccessPolicy {
					netpol := gaia.NewNetworkAccessPolicy()
					netpol.Name = "name"
					netpol.Namespace = "namespace"
					netpol.ApplyPolicyMode = gaia.NetworkAccessPolicyApplyPolicyModeOutgoingTraffic
					netpol.Action = gaia.NetworkAccessPolicyActionAllow
					netpol.Subject = [][]string{{"app=foo"}}
					netpol.Object = [][]string{{"app=bar"}}
					netpol.Ports = []string{"tcp/80:90"} // If we have ports already defined in policy, they will be intersected with external network.
					return netpol
				}(),
				extnet: gaia.ExternalNetworksList{
					{
						Name:           "e1",
						AssociatedTags: []string{"app=bar"},
						Entries:        []string{"10.10.10.10/32"},
						ServicePorts:   []string{"tcp/80"},
					},
				},
			},
			wantOutNetPolList: gaia.NetworkRuleSetPoliciesList{
				{
					Name:      "name",
					Namespace: "namespace",
					Subject:   [][]string{{"app=foo"}},
					OutgoingRules: []*gaia.NetworkRule{
						{
							Action:        gaia.NetworkRuleActionAllow,
							Object:        [][]string{{"app=bar", "$identity=externalnetwork", "$name=e1", "version=v2"}},
							ProtocolPorts: []string{"tcp/80"},
						},
					},
				},
			},
			wantOutExtNetList: gaia.ExternalNetworksList{
				{
					Name:           "e1",
					AssociatedTags: []string{"app=bar", "version=v2"},
					Entries:        []string{"10.10.10.10/32"},
					ServicePorts:   []string{"tcp/80"},
				},
			},
		},
		{
			name: "allow outgoing ACL network policy with external networks (ports/protocol intersection with ranges)",
			args: args{
				netpol: func() *gaia.NetworkAccessPolicy {
					netpol := gaia.NewNetworkAccessPolicy()
					netpol.Name = "name"
					netpol.Namespace = "namespace"
					netpol.ApplyPolicyMode = gaia.NetworkAccessPolicyApplyPolicyModeOutgoingTraffic
					netpol.Action = gaia.NetworkAccessPolicyActionAllow
					netpol.Subject = [][]string{{"app=foo"}}
					netpol.Object = [][]string{{"app=bar"}}
					netpol.Ports = []string{"tcp/80:90"} // If we have ports already defined in policy, they will be intersected with external network.
					return netpol
				}(),
				extnet: gaia.ExternalNetworksList{
					{
						Name:           "e1",
						AssociatedTags: []string{"app=bar"},
						Entries:        []string{"10.10.10.10/32"},
						ServicePorts:   []string{"tcp/78:81"},
					},
				},
			},
			wantOutNetPolList: gaia.NetworkRuleSetPoliciesList{
				{
					Name:      "name",
					Namespace: "namespace",
					Subject:   [][]string{{"app=foo"}},
					OutgoingRules: []*gaia.NetworkRule{
						{
							Action:        gaia.NetworkRuleActionAllow,
							Object:        [][]string{{"app=bar", "$identity=externalnetwork", "$name=e1", "version=v2"}},
							ProtocolPorts: []string{"tcp/80:81"}, // Intersection is much smaller than what was originally in the policy.
						},
					},
				},
			},
			wantOutExtNetList: gaia.ExternalNetworksList{
				{
					Name:           "e1",
					AssociatedTags: []string{"app=bar", "version=v2"},
					Entries:        []string{"10.10.10.10/32"},
					ServicePorts:   []string{"tcp/78:81"},
				},
			},
		},
		{
			name: "allow outgoing ACL network policy with multiple external networks (ports/protocol intersection with ranges)",
			args: args{
				netpol: func() *gaia.NetworkAccessPolicy {
					netpol := gaia.NewNetworkAccessPolicy()
					netpol.Name = "name"
					netpol.Namespace = "namespace"
					netpol.ApplyPolicyMode = gaia.NetworkAccessPolicyApplyPolicyModeOutgoingTraffic
					netpol.Action = gaia.NetworkAccessPolicyActionAllow
					netpol.Subject = [][]string{{"app=foo"}}
					netpol.Object = [][]string{{"app=bar"}}
					netpol.Ports = []string{"tcp/80:90"} // If we have ports already defined in policy, they will be intersected with external network.
					return netpol
				}(),
				extnet: gaia.ExternalNetworksList{
					{
						ID:             "x1",
						Name:           "x2",
						AssociatedTags: []string{"app=bar"},
						Entries:        []string{"10.10.10.10/32"},
						ServicePorts:   []string{"tcp/78:81"},
					},
					{
						ID:             "y1",
						Name:           "y2",
						AssociatedTags: []string{"app=bar"},
						Entries:        []string{"11.11.11.11/32"},
						ServicePorts:   []string{"tcp/80"},
					},
				},
			},
			wantOutNetPolList: gaia.NetworkRuleSetPoliciesList{
				{
					Name:      "name",
					Namespace: "namespace",
					Subject:   [][]string{{"app=foo"}},
					OutgoingRules: []*gaia.NetworkRule{
						{
							Action:        gaia.NetworkRuleActionAllow,
							Object:        [][]string{{"app=bar", externalNetworkKey, "$name=x2", "version=v2"}},
							ProtocolPorts: []string{"tcp/80:81"}, // Intersection is much smaller than what was originally in the policy.
						},
						{
							Action:        gaia.NetworkRuleActionAllow,
							Object:        [][]string{{"app=bar", externalNetworkKey, "$name=y2", "version=v2"}},
							ProtocolPorts: []string{"tcp/80"}, // Intersection is much smaller than what was originally in the policy.
						},
					},
				},
			},
			wantOutExtNetList: gaia.ExternalNetworksList{
				{
					AssociatedTags: []string{"app=bar", "version=v2"},
					Entries:        []string{"10.10.10.10/32"},
					ServicePorts:   []string{"tcp/78:81"},
				},
				{
					AssociatedTags: []string{"app=bar", "version=v2"},
					Entries:        []string{"11.11.11.11/32"},
					ServicePorts:   []string{"tcp/80"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOutNetPolList, gotOutExtNetList := ConvertToNetworkRuleSetPolicies(tt.args.netpol, tt.args.extnet)
			if len(gotOutNetPolList) != len(tt.wantOutNetPolList) {
				t.Errorf("ConvertToNetworkRuleSetPolicies() len(gotOutNetPolList) = %v, doesn't match len(tt.wantOutNetPolList) %v", len(gotOutExtNetList), len(tt.wantOutNetPolList))
			}
			if len(gotOutExtNetList) != len(tt.wantOutExtNetList) {
				t.Errorf("ConvertToNetworkRuleSetPolicies() len(gotOutNetPolList) = %v, doesn't match len(tt.wantOutNetPolList) %v", len(gotOutExtNetList), len(tt.wantOutNetPolList))
			}
			for _, policy := range gotOutNetPolList {
				matched := false
				for _, want := range tt.wantOutNetPolList {
					if want.Name != policy.Name {
						continue
					}
					if want.Namespace != policy.Namespace {
						continue
					}
					if len(want.IncomingRules) != len(policy.IncomingRules) {
						continue
					}
					if len(want.OutgoingRules) != len(policy.OutgoingRules) {
						continue
					}
					if !reflect.DeepEqual(want.Subject, policy.Subject) {
						continue
					}

					if len(policy.IncomingRules) != 0 {
						irulesMatched := false
						for _, irule := range policy.IncomingRules {
							for _, iwant := range want.IncomingRules {
								if !matchObjects(iwant.Object, irule.Object) {
									continue
								}
								if !matchTags(iwant.ProtocolPorts, irule.ProtocolPorts) {
									continue
								}
								irulesMatched = true
							}
						}
						if !irulesMatched {
							continue
						}
					}

					if len(policy.OutgoingRules) != 0 {
						orulesMatched := false
						for _, orule := range policy.OutgoingRules {
							for _, owant := range want.OutgoingRules {
								if !matchObjects(owant.Object, orule.Object) {
									continue
								}
								if !matchTags(owant.ProtocolPorts, orule.ProtocolPorts) {
									continue
								}
								orulesMatched = true
							}
						}
						if !orulesMatched {
							continue
						}
					}

					matched = true
				}
				if !matched {
					t.Errorf("ConvertToNetworkRuleSetPolicies() policy = %+v not found list: %+v", *policy, *gotOutNetPolList[0])
					if len(policy.IncomingRules) > 0 {
						t.Errorf("irobj: %v/%v", policy.IncomingRules[0].Object, gotOutNetPolList[0].IncomingRules[0].Object)
					}
					if len(policy.OutgoingRules) > 0 {
						t.Errorf("orobj: %v/%v", policy.OutgoingRules[0].Object, gotOutNetPolList[0].OutgoingRules[0].Object)
					}
				}
			}
			for _, extnet := range gotOutExtNetList {
				matched := false
				for _, want := range tt.wantOutExtNetList {
					if !reflect.DeepEqual(want.AssociatedTags, extnet.AssociatedTags) {
						continue
					}
					if !reflect.DeepEqual(want.ServicePorts, extnet.ServicePorts) {
						continue
					}
					matched = true
				}
				if !matched {
					t.Errorf("ConvertToNetworkRuleSetPolicies() external-network = %+v not found list: %+v", *extnet, *gotOutExtNetList[0])
				}
			}
		})
	}
}

func matchTags(want, got []string) bool {

	if len(want) != len(got) {
		return false
	}

	for _, wantTag := range want {
		matched := false
		for _, gotTag := range got {
			if wantTag == gotTag {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
func matchObjects(want, got [][]string) bool {

	if len(want) != len(got) {
		return false
	}

	matched := false
	for _, wantObj := range want {
		for _, gotObj := range got {
			if matchTags(wantObj, gotObj) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
