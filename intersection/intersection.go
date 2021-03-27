package intersection

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go.aporeto.io/gaia"
	"go.aporeto.io/gaia/protocols"
	"go.uber.org/zap"
)

// ALLPORTS is a const definition for all ports in a given protocol
const ALLPORTS = "1:65535"

// IntersectedICMP removes all ICMPs from existing slices and returns the intersection of ICMPs and slices sans ICMP entries.
func IntersectedICMP(servicePorts []string, restrictedPorts []string) ([]string, []string, []string) {

	filterICMP := func(l []string) (map[string]struct{}, []string, bool) {
		var others []string
		var hasAny bool

		icmps := map[string]struct{}{}

		for _, v := range l {
			if strings.Contains(strings.ToUpper(v), protocols.L4ProtocolICMP) ||
				strings.Contains(strings.ToUpper(v), protocols.L4ProtocolICMP6) {
				for _, icmp := range splitICMPProto(v, 1) {
					icmps[strings.ToLower(icmp)] = struct{}{}
				}
			} else {
				if strings.EqualFold(v, protocols.ANY) {
					hasAny = true
				}
				others = append(others, v)
			}
		}

		return icmps, others, hasAny
	}

	serviceICMPs, servicePortsSansICMP, servicePortsHasAny := filterICMP(servicePorts)
	restrictedICMPs, restrictedPortsSansICMP, restrictedPortsHasAny := filterICMP(restrictedPorts)

	icmps := map[string]map[string]struct{}{}

	for icmp := range serviceICMPs {
		if _, ok := restrictedICMPs[icmp]; !ok && len(restrictedPorts) != 0 && !restrictedPortsHasAny {
			continue
		}

		parts := strings.Split(icmp, "/")

		if len(parts) < 3 {
			if _, ok := icmps[icmp]; !ok {
				icmps[icmp] = nil
			}
			continue
		}

		icmpType := fmt.Sprintf("%s/%s", parts[0], parts[1])

		if icmps[icmpType] == nil {
			icmps[icmpType] = map[string]struct{}{}
		}
		icmps[icmpType][parts[2]] = struct{}{}
	}

	for icmp := range restrictedICMPs {
		if _, ok := serviceICMPs[icmp]; !ok && len(servicePorts) != 0 && !servicePortsHasAny {
			continue
		}

		parts := strings.Split(icmp, "/")

		if len(parts) < 3 {
			if _, ok := icmps[icmp]; !ok {
				icmps[icmp] = nil
			}
			continue
		}

		icmpType := fmt.Sprintf("%s/%s", parts[0], parts[1])

		if icmps[icmpType] == nil {
			icmps[icmpType] = map[string]struct{}{}
		}
		icmps[icmpType][parts[2]] = struct{}{}
	}

	intersectedICMPs := make([]string, len(icmps))
	var i int
	for icmpType, icmpCodes := range icmps {
		if len(icmpCodes) == 0 {
			intersectedICMPs[i] = icmpType
			i++
			continue
		}

		icmp := icmpType + "/"

		codes := make([]string, len(icmpCodes))
		var ii int
		for code := range icmpCodes {
			codes[ii] = code
			ii++
		}
		sort.Strings(codes)

		for _, code := range codes {
			icmp += code + ","
		}
		intersectedICMPs[i] = strings.TrimSuffix(icmp, ",")
		i++
	}

	sort.Strings(intersectedICMPs)

	return intersectedICMPs, servicePortsSansICMP, restrictedPortsSansICMP
}

// splitICMPProto splits an ICMP into its separate codes
func splitICMPProto(proto string, maxCodes int) []string {

	splits := strings.Split(proto, "/")

	if len(splits) < 3 {
		return []string{proto}
	}

	baseString := strings.Join(splits[:2], "/") + "/"

	codes := splits[2]
	csvSplits := strings.Split(codes, ",")

	coll := [][]string{}
	count := 0
	lencsv := len(csvSplits)

	for i := 0; i < lencsv; i++ {
		count++
		if count%maxCodes == 0 {
			coll = append(coll, csvSplits[:count])
			csvSplits = csvSplits[count:]
			count = 0
		}
	}

	if len(csvSplits) != 0 {
		coll = append(coll, csvSplits)
	}

	splitICMPStrings := []string{}

	for _, s := range coll {
		splitICMPStrings = append(splitICMPStrings, baseString+strings.Join(s, ","))
	}

	return splitICMPStrings
}

// ExtractProtocolsPorts is a helper function to extract ports for a given protocol from servicePorts.
// It also returns list of protocols excluding TCP and UDP (i.e. protocols with no ports).
// The ports is a map of n entries with each n has 15 elements.
// NOTE: This is required because the iptables `--multiport `
// supports only a maximum of 15 disjoint ports in a single rule.
func ExtractProtocolsPorts(protocol string, servicePorts []string, restrictedPortList []string) ([]string, []string) {

	restrictedPortsMap := map[int]struct{}{}
	filteredServicePorts := map[int]struct{}{}

	restrictedProtocols := map[string]struct{}{}
	serviceProtocols := map[string]struct{}{}

	// foundalternate points to condition where ext networks
	var foundalternate bool
	for _, restrictedPort := range restrictedPortList {
		rprotocol, rports, err := parseServicePort(restrictedPort)
		if err != nil {
			zap.L().Error("unable to parse restrictedPort", zap.Error(err))
			continue
		}

		if !strings.EqualFold(rprotocol, protocols.L4ProtocolTCP) && !strings.EqualFold(rprotocol, protocols.L4ProtocolUDP) {
			if !strings.EqualFold(rprotocol, protocols.ANY) {
				restrictedProtocols[strings.ToUpper(rprotocol)] = struct{}{}
				continue
			}
			restrictedProtocols[strings.ToUpper(rprotocol)] = struct{}{}
		}

		if strings.EqualFold(rprotocol, protocols.ANY) && protocol != "" {
			rprotocol = protocol
			rports = ALLPORTS
		}

		if !strings.EqualFold(protocol, rprotocol) {
			foundalternate = true
			continue
		}

		portSpec, err := NewPortSpecFromString(rports, nil)
		if err != nil {
			continue
		}

		for port := uint32(portSpec.Min); port <= uint32(portSpec.Max); port++ {
			restrictedPortsMap[int(port)] = struct{}{}
		}
	}

	if foundalternate && len(restrictedPortsMap) == 0 {
		restrictedPortsMap[0] = struct{}{}
	}

	for _, servicePort := range servicePorts {

		sprotocol, sports, err := parseServicePort(servicePort)
		if err != nil {
			zap.L().Error("unable to parse servicePort", zap.Error(err))
			continue
		}

		if !strings.EqualFold(sprotocol, protocols.L4ProtocolTCP) && !strings.EqualFold(sprotocol, protocols.L4ProtocolUDP) {
			if !strings.EqualFold(sprotocol, protocols.ANY) {
				serviceProtocols[strings.ToUpper(sprotocol)] = struct{}{}
				continue
			}
			serviceProtocols[strings.ToUpper(sprotocol)] = struct{}{}
		}

		if strings.EqualFold(sprotocol, protocols.ANY) && protocol != "" {
			sprotocol = protocol
			sports = ALLPORTS
		}

		if !strings.EqualFold(sprotocol, protocol) {
			continue
		}

		portSpec, err := NewPortSpecFromString(sports, nil)
		if err != nil {
			continue
		}

		for port := uint32(portSpec.Min); port <= uint32(portSpec.Max); port++ {
			filteredServicePorts[int(port)] = struct{}{}
		}
	}

	intersectedPorts := TrimPortRange(filteredServicePorts, restrictedPortsMap)

	intersectedProtocols := intersectedProtocols(serviceProtocols, restrictedProtocols)

	return intersectedProtocols, intersectedPorts
}

// parseServicePort returns protocol and ports from servicePort.
func parseServicePort(servicePort string) (string, string, error) {

	if err := gaia.ValidateServicePort("servicePort", servicePort); err != nil {
		return "", "", err
	}

	parts := strings.SplitN(servicePort, "/", 2)
	protocol := parts[0]

	ports := ""

	if len(parts) == 2 {
		ports = parts[1]
	}

	return protocol, ports, nil
}

// PortSpec is the specification of a port or port range
type PortSpec struct {
	Min   uint16 `json:"Min,omitempty"`
	Max   uint16 `json:"Max,omitempty"`
	value interface{}
}

// NewPortSpec creates a new port spec
func NewPortSpec(min, max uint16, value interface{}) (*PortSpec, error) {

	if min > max {
		return nil, fmt.Errorf("Min port greater than max")
	}

	return &PortSpec{
		Min:   min,
		Max:   max,
		value: value,
	}, nil
}

// NewPortSpecFromString creates a new port spec
func NewPortSpecFromString(ports string, value interface{}) (*PortSpec, error) {

	var min, max int
	var err error
	if strings.Contains(ports, ":") {
		portMinMax := strings.SplitN(ports, ":", 2)
		if len(portMinMax) != 2 {
			return nil, fmt.Errorf("Invalid port specification")
		}

		min, err = strconv.Atoi(portMinMax[0])
		if err != nil || min < 0 {
			return nil, fmt.Errorf("Min is not a valid port")
		}

		max, err = strconv.Atoi(portMinMax[1])
		if err != nil || max >= 65536 {
			return nil, fmt.Errorf("Max is not a valid port")
		}
	} else {
		min, err = strconv.Atoi(ports)
		if err != nil || min >= 65536 || min < 0 {
			return nil, fmt.Errorf("Port is larger than 2^16 or invalid port")
		}
		max = min
	}

	return NewPortSpec(uint16(min), uint16(max), value)
}

// TrimPortRange returns ranges such that if no entries in exist in filteredPortMap, the
// complete sports are returned. However, if filteredPortMap has entries, the ranges
// returned are intersection of sports and filteredPortMap.
func TrimPortRange(filteredServicePorts map[int]struct{}, filteredPortMap map[int]struct{}) []string {

	servicePorts := make([]int, len(filteredServicePorts))

	var i int
	for port := range filteredServicePorts {
		servicePorts[i] = port
		i++
	}
	sort.Ints(servicePorts)

	// return early if there are no ports in policy
	// remove this when we remove ports from ext networks
	if len(filteredPortMap) == 0 {
		return []string{}
	}

	// single value
	if len(servicePorts) == 1 {
		if _, ok := filteredPortMap[servicePorts[0]]; ok {
			return buildRanges(servicePorts)
		}
		return []string{}
	}

	// range
	includePorts := []int{}
	for _, port := range servicePorts {
		if _, ok := filteredPortMap[port]; !ok {
			continue
		}
		includePorts = append(includePorts, port)
	}

	return buildRanges(includePorts)
}

// fmtRange will return a string array with one member in the form
// - { "start:end" } when start and end are two different numbers
// - { "start" } when start and end are same number
func fmtRange(start, end int) []string {
	r := ""
	if start != end {
		r = fmt.Sprintf("%d:%d", start, end)
	} else {
		r = strconv.Itoa(start)
	}
	return []string{r}
}

// buildRangesR is a recursive function to return a list of ranges
// representing the numbers in the ports list.
// ports list is expected to be sorted in ascending order.
func buildRangesR(ports []int, start, curr int) []string {
	if len(ports) == 1 {
		return fmtRange(start, curr)
	}
	// len(ports) > 1
	sports := []string{}
	if ports[0]+1 != ports[1] {
		sports = fmtRange(start, curr)
		start = ports[1]
	}
	return append(sports, buildRangesR(ports[1:], start, ports[1])...)
}

// buildRanges returns a list of ranges to represent ports in the ports list.
// ports list is expected to be sorted in ascending order.
func buildRanges(ports []int) []string {
	if len(ports) == 0 {
		return []string{}
	}
	return buildRangesR(ports, ports[0], ports[0])
}

// intersectedProtocols returns the intersection of the service and restricted protocols.
func intersectedProtocols(serviceProtocols map[string]struct{}, restrictedProtocols map[string]struct{}) []string {

	_, restrictedHasAny := restrictedProtocols[protocols.ANY]
	_, serviceHasAny := serviceProtocols[protocols.ANY]

	if restrictedHasAny && serviceHasAny {
		return []string{protocols.ANY}
	}

	intersectedProtocols := []string{}

	if !restrictedHasAny {
		for restrictedProtocol := range restrictedProtocols {
			if _, ok := serviceProtocols[restrictedProtocol]; !ok && !serviceHasAny {
				continue
			}

			intersectedProtocols = append(intersectedProtocols, restrictedProtocol)
		}
	}

	if restrictedHasAny && !serviceHasAny {
		for serviceProtocol := range serviceProtocols {
			intersectedProtocols = append(intersectedProtocols, serviceProtocol)
		}
	}

	sort.Strings(intersectedProtocols)

	return intersectedProtocols
}
