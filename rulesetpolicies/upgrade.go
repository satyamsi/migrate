package rulesetpolicies

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/satyamsi/migrate/intersection"
	"go.aporeto.io/gaia"
	"go.aporeto.io/gaia/protocols"
)

const (
	// anyKey is the key representation for any ports/protocols
	anyKey = "any"

	// externalNetworkKey is the key representation for external network identity key
	externalNetworkKey = "$identity=externalnetwork"

	// ineffectiveKey represents the key that labels network rules that are not meaningful
	ineffectiveKey = "policy=ineffective"
)

// ConvertToNetworkRuleSetPolicies converts a network access policy to one or more network rule set policies.
func ConvertToNetworkRuleSetPolicies(
	netpol *gaia.NetworkAccessPolicy,
	extnet gaia.ExternalNetworksList,
) (
	outNetPolList gaia.NetworkRuleSetPoliciesList,
	outExtNetList gaia.ExternalNetworksList,
) {

	outNetPolList = gaia.NetworkRuleSetPoliciesList{}
	outExtNetList = gaia.ExternalNetworksList{}

	// If action is `Continue` we will ignore these as there is no translation
	if netpol.Action == gaia.NetworkAccessPolicyActionContinue {
		return outNetPolList, outExtNetList
	}

	networkRuleSetPolicy := gaia.NewNetworkRuleSetPolicy()
	networkRuleSetPolicy.Name = netpol.Name
	networkRuleSetPolicy.Namespace = netpol.Namespace
	networkRuleSetPolicy.Description = netpol.Description
	networkRuleSetPolicy.Disabled = netpol.Disabled
	networkRuleSetPolicy.Protected = netpol.Protected
	networkRuleSetPolicy.Propagate = netpol.Propagate
	networkRuleSetPolicy.Fallback = netpol.Fallback
	networkRuleSetPolicy.AssociatedTags = netpol.AssociatedTags
	networkRuleSetPolicy.Metadata = netpol.Metadata
	networkRuleSetPolicy.Annotations = netpol.Annotations

	now := time.Now().Round(time.Millisecond)
	networkRuleSetPolicy.CreateTime = now
	networkRuleSetPolicy.UpdateTime = now

	networkRule := gaia.NewNetworkRule()
	networkRule.Action = convertToNetworkRuleAction(netpol.Action)
	networkRule.LogsDisabled = !netpol.LogsEnabled
	networkRule.ProtocolPorts = netpol.Ports
	// NOTE: We have no conversion for ObservedTrafficAction
	networkRule.ObservationEnabled = netpol.ObservationEnabled

	// Bidirectional policies require two rule set policies:
	// 1) An incoming rule set policy from the object to the subject
	// 2) An outgoing rule set policy from the subject to the object
	// The other ApplyPolicyMode choices align with 1) or 2) alone
	if netpol.ApplyPolicyMode == gaia.NetworkAccessPolicyApplyPolicyModeIncomingTraffic ||
		netpol.ApplyPolicyMode == gaia.NetworkAccessPolicyApplyPolicyModeBidirectional {
		// Incoming rule set policies
		for _, subject := range netpol.Object {
			// Create a new rule set policy
			policy := networkRuleSetPolicy.DeepCopy()
			policy.Subject = [][]string{subject}
			policy.IncomingRules = make([]*gaia.NetworkRule, len(netpol.Subject))

			// Create a rule for each 'OR' clause
			for i, object := range netpol.Subject {
				rule := networkRule.DeepCopy()
				rule.Object = [][]string{object}
				policy.IncomingRules[i] = rule
			}

			policy.NormalizedTags = netpol.NormalizedTags
			outNetPolList = append(outNetPolList, policy)
		}
	}

	if netpol.ApplyPolicyMode == gaia.NetworkAccessPolicyApplyPolicyModeOutgoingTraffic ||
		netpol.ApplyPolicyMode == gaia.NetworkAccessPolicyApplyPolicyModeBidirectional {
		// Outgoing rule set policies
		for _, subject := range netpol.Subject {

			policy := networkRuleSetPolicy.DeepCopy()
			policy.Subject = [][]string{subject}
			policy.OutgoingRules = make([]*gaia.NetworkRule, len(netpol.Object))

			// Create a rule for each 'OR' clause
			for i, object := range netpol.Object {
				rule := networkRule.DeepCopy()
				rule.Object = [][]string{object}
				policy.OutgoingRules[i] = rule
			}

			policy.NormalizedTags = netpol.NormalizedTags
			outNetPolList = append(outNetPolList, policy)
		}
	}

	outExtNetList = addExternalNetworkToPolicies(outNetPolList, extnet)

	return outNetPolList, outExtNetList
}

// convertNetPolActionToNetRuleAction converts a network access policy action into its corresponding network rule action.
func convertToNetworkRuleAction(action gaia.NetworkAccessPolicyActionValue) gaia.NetworkRuleActionValue {

	switch action {
	case gaia.NetworkAccessPolicyActionAllow:
		return gaia.NetworkRuleActionAllow
	case gaia.NetworkAccessPolicyActionReject:
		return gaia.NetworkRuleActionReject
	default:
		panic(fmt.Sprintf("unsupported network access policy action: '%s'", action))
	}
}

func addExternalNetworkToPolicies(
	netpols gaia.NetworkRuleSetPoliciesList,
	extnets gaia.ExternalNetworksList,
) (
	outExtNetList gaia.ExternalNetworksList,
) {
	for _, policy := range netpols {
		networks := addExternalNetworks(policy, extnets)
		outExtNetList = append(outExtNetList, networks...)
	}
	return outExtNetList
}

// addExternalNetworks looks up the relevant external networks and returns the union of ports and protocols as actions.
func addExternalNetworks(policy *gaia.NetworkRuleSetPolicy, extnets gaia.ExternalNetworksList) (networks gaia.ExternalNetworksList) {

	rules := []*gaia.NetworkRule{}
	networks = gaia.ExternalNetworksList{}
	for _, rule := range policy.IncomingRules {
		expandedRules, expandedNetworks := expandNetworkRule(rule, extnets)
		rules = append(rules, expandedRules...)
		networks = append(networks, expandedNetworks...)
	}
	policy.IncomingRules = rules

	rules = []*gaia.NetworkRule{}
	for _, rule := range policy.OutgoingRules {
		expandedRules, expandedNetworks := expandNetworkRule(rule, extnets)
		rules = append(rules, expandedRules...)
		networks = append(networks, expandedNetworks...)
	}
	policy.OutgoingRules = rules
	return networks
}

func externalNetworksMatchTags(extnet *gaia.ExternalNetwork, tags []string) bool {

	for _, tag := range tags {
		matched := false

		// Policy has some other identity match than $identity=externalnetwork. This set of tags can not match an external network
		if strings.HasPrefix(tag, "$identity=") && !strings.EqualFold(tag, externalNetworkKey) {
			return false
		}

		// Policy has namespace match
		if strings.HasPrefix(tag, "$namespace=") {
			continue
		}

		// Policy has id match
		if strings.HasPrefix(tag, "$id=") {
			continue
		}

		// Some unknown $ match, panic here as opposed to recovering
		if strings.HasPrefix(tag, "$") {
			panic("unhandled tag")
		}

		for _, etag := range extnet.AssociatedTags {
			if etag == tag {
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

func getMatchingExternalNetworks(objects [][]string, extnets gaia.ExternalNetworksList) (match gaia.ExternalNetworksList) {

	for _, extnet := range extnets {
		matched := false
		for _, object := range objects {
			if externalNetworksMatchTags(extnet, object) {
				matched = true
				break
			}
		}
		if matched {
			extnetCopy := extnet.DeepCopy()
			extnetCopy.AssociatedTags = append(extnetCopy.AssociatedTags, "version=v2")
			match = append(match, extnetCopy)
		}
	}
	return match
}

// expandNetworkRule takes the intersection of each related external network's protocols/ports with the network rule and makes a new rule for each external network.
func expandNetworkRule(rule *gaia.NetworkRule, extnets gaia.ExternalNetworksList) ([]*gaia.NetworkRule, gaia.ExternalNetworksList) {

	matchingExtNets := getMatchingExternalNetworks(rule.Object, extnets)

	if len(matchingExtNets) == 0 {
		return []*gaia.NetworkRule{rule}, matchingExtNets
	}

	// Create a map to avoid duplicate entries
	protocolsAndPorts := map[string]struct{}{}

	// If no protocols, then this is essentially an any, so set it as much for later logic
	if len(rule.ProtocolPorts) == 0 {
		rule.ProtocolPorts = []string{anyKey}
	}

	for _, entry := range rule.ProtocolPorts {
		// Force set the 'any' to a case we can trust
		if strings.EqualFold(entry, anyKey) {
			rule.ProtocolPorts = []string{anyKey}
			break
		}

		protocolsAndPorts[strings.ToLower(entry)] = struct{}{}
	}

	rules := []*gaia.NetworkRule{}

	for _, externalNetwork := range matchingExtNets {

		for _, entry := range externalNetwork.ServicePorts {
			// Force set the 'any' to a case we can trust
			if strings.EqualFold(entry, anyKey) {
				externalNetwork.ServicePorts = []string{anyKey}
				break
			}
		}

		// Assume `any` if no service ports are set
		if len(externalNetwork.ServicePorts) == 0 {
			externalNetwork.ServicePorts = []string{anyKey}
		}

		protocolAndPorts := protocolPortsIntersection(rule.ProtocolPorts, externalNetwork.ServicePorts)

		newRule := rule.DeepCopy()
		for i, objects := range newRule.Object {
			// Remove externalnetwork and id tag if exists in list
			o := objects[:0]
			for _, object := range objects {
				if strings.EqualFold(object, externalNetworkKey) {
					continue
				}

				o = append(o, object)
			}

			newRule.Object[i] = append(o, externalNetworkKey, "$name="+externalNetwork.Name, "version=v2")
		}

		newRule.ProtocolPorts = protocolAndPorts

		// This rule is ineffective, label as such
		if len(newRule.ProtocolPorts) == 0 {
			newRule.Object = append(newRule.Object, []string{ineffectiveKey})
		}

		rules = append(rules, newRule)
	}

	if len(rules) == 0 {
		return []*gaia.NetworkRule{rule}, matchingExtNets
	}

	return rules, matchingExtNets
}

// intersection finds and returns the intersection of ports across protocols
func protocolPortsIntersection(ruleProtocolPorts []string, extnetProtocolPorts []string) []string {

	icmps, extnetProtoPortsSubset, ruleProtoPortsSubset := intersection.IntersectedICMP(extnetProtocolPorts, ruleProtocolPorts)

	miscProtocols, _ := intersection.ExtractProtocolsPorts("", extnetProtoPortsSubset, ruleProtoPortsSubset)

	// If 'any' is part of miscProtocols, then we are done
	for _, protocol := range miscProtocols {
		if strings.EqualFold(protocol, anyKey) {
			return []string{protocol}
		}
	}

	_, tcpPorts := intersection.ExtractProtocolsPorts(protocols.L4ProtocolTCP, extnetProtoPortsSubset, ruleProtoPortsSubset)
	for i, tcpPort := range tcpPorts {
		tcpPorts[i] = fmt.Sprintf("tcp/%s", tcpPort)
	}

	_, udpPorts := intersection.ExtractProtocolsPorts(protocols.L4ProtocolUDP, extnetProtoPortsSubset, ruleProtoPortsSubset)
	for i, udpPort := range udpPorts {
		udpPorts[i] = fmt.Sprintf("udp/%s", udpPort)
	}

	intersectedProtocolPorts := append(icmps, tcpPorts...)
	intersectedProtocolPorts = append(intersectedProtocolPorts, udpPorts...)
	intersectedProtocolPorts = append(intersectedProtocolPorts, miscProtocols...)

	sort.Strings(intersectedProtocolPorts)

	return intersectedProtocolPorts
}
