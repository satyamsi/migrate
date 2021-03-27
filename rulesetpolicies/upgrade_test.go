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
			name: "allow unidirectional identity network policy with no matching external networks",
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
					Subject:   [][]string{{"app=foo"}},
					IncomingRules: []*gaia.NetworkRule{
						{
							Action: gaia.NetworkRuleActionAllow,
							Object: [][]string{{"app=bar"}},
						},
					},
				},
			},
			wantOutExtNetList: gaia.ExternalNetworksList{},
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
					matched = true
				}
				if !matched {
					t.Errorf("ConvertToNetworkRuleSetPolicies() policy = %v not found", *policy)
				}
			}
		})
	}
}
