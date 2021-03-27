package intersection

import (
	"reflect"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_IntersectedICMP(t *testing.T) {
	type args struct {
		servicePorts    []string
		restrictedPorts []string
	}
	tests := []struct {
		name           string
		args           args
		wantICMP       []string
		wantService    []string
		wantRestricted []string
	}{
		{"1", args{[]string{"icmp"}, []string{"icmp"}}, []string{"icmp"}, nil, nil},
		{"2", args{[]string{"icmp6"}, []string{"icmp", "icmp6"}}, []string{"icmp6"}, nil, nil},
		{"3", args{[]string{"icmp", "icmp6"}, []string{"icmp"}}, []string{"icmp"}, nil, nil},
		{"4", args{[]string{"icmp/1/2,3,4,5", "icmp6"}, []string{"icmp/1/2,3"}}, []string{"icmp/1/2,3"}, nil, nil},
		{"5", args{[]string{"icmp/1/3", "icmp/1/5", "icmp6"}, []string{"icmp/1/2,3,4,5"}}, []string{"icmp/1/3,5"}, nil, nil},
		{"6", args{[]string{}, []string{"icmp/2/1,3"}}, []string{"icmp/2/1,3"}, nil, nil},
		{"7", args{[]string{"tcp/80", "udp/90", "icmp/1/2"}, []string{"icmp/1/2", "tcp/90", "udp/100", "igmp"}}, []string{"icmp/1/2"}, []string{"tcp/80", "udp/90"}, []string{"tcp/90", "udp/100", "igmp"}},
		{"8", args{[]string{"tcp/80", "udp/90", "icmp/1/2"}, []string{"tcp/90", "udp/100", "igmp"}}, []string{}, []string{"tcp/80", "udp/90"}, []string{"tcp/90", "udp/100", "igmp"}},
		{"9", args{[]string{"icmp", "icmp6"}, []string{}}, []string{"icmp", "icmp6"}, nil, nil},
		{"10", args{[]string{}, []string{"icmp", "icmp6"}}, []string{"icmp", "icmp6"}, nil, nil},
		{"11", args{[]string{"any"}, []string{"icmp", "icmp6"}}, []string{"icmp", "icmp6"}, []string{"any"}, nil},
		{"12", args{[]string{"icmp", "icmp6"}, []string{"any"}}, []string{"icmp", "icmp6"}, nil, []string{"any"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotICMP, gotService, gotRestricted := IntersectedICMP(tt.args.servicePorts, tt.args.restrictedPorts)
			if !reflect.DeepEqual(gotICMP, tt.wantICMP) {
				t.Errorf("IntersectedICMP() = %v, wantICMP %v", gotICMP, tt.wantICMP)
			}
			if !reflect.DeepEqual(gotService, tt.wantService) {
				t.Errorf("IntersectedICMP() = %v, wantService %v", gotService, tt.wantService)
			}
			if !reflect.DeepEqual(gotRestricted, tt.wantRestricted) {
				t.Errorf("IntersectedICMP() = %v, wantRestricted %v", gotRestricted, tt.wantRestricted)
			}
		})
	}
}

func Test_splitICMPProto(t *testing.T) {
	type args struct {
		proto    string
		maxCodes int
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"1", args{"icmp", 2}, []string{"icmp"}},
		{"2", args{"icmp6", 2}, []string{"icmp6"}},
		{"3", args{"icmp/1", 2}, []string{"icmp/1"}},
		{"4", args{"icmp/1/2", 2}, []string{"icmp/1/2"}},
		{"4", args{"icmp/1/2,3", 2}, []string{"icmp/1/2,3"}},
		{"5", args{"icmp/1/2,3,4", 2}, []string{"icmp/1/2,3", "icmp/1/4"}},
		{"6", args{"icmp/1/2,3,4,5", 2}, []string{"icmp/1/2,3", "icmp/1/4,5"}},
		{"7", args{"icmp/1/2,3,4,5,6", 2}, []string{"icmp/1/2,3", "icmp/1/4,5", "icmp/1/6"}},
		{"8", args{"icmp/1/2,3,4,5,6,7", 2}, []string{"icmp/1/2,3", "icmp/1/4,5", "icmp/1/6,7"}},
		{"9", args{"icmp6/1", 2}, []string{"icmp6/1"}},
		{"10", args{"icmp6/1/2", 2}, []string{"icmp6/1/2"}},
		{"11", args{"icmp6/1/2,3", 2}, []string{"icmp6/1/2,3"}},
		{"12", args{"icmp6/1/2,3,4", 2}, []string{"icmp6/1/2,3", "icmp6/1/4"}},
		{"13", args{"icmp6/1/2,3,4,5", 2}, []string{"icmp6/1/2,3", "icmp6/1/4,5"}},
		{"14", args{"icmp6/1/2,3,4,5,6", 2}, []string{"icmp6/1/2,3", "icmp6/1/4,5", "icmp6/1/6"}},
		{"15", args{"icmp6/1/2,3,4,5,6,7", 2}, []string{"icmp6/1/2,3", "icmp6/1/4,5", "icmp6/1/6,7"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitICMPProto(tt.args.proto, tt.args.maxCodes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitICMPProto() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ExtractProtocolsPorts(t *testing.T) {

	Convey("Given I call ExtractProtocolsPorts with max port", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp", []string{"tcp/1:65535"}, []string{"tcp/1:65535"})

		Convey("Then data should be right", func() {
			So(protocols, ShouldBeEmpty)
			So(len(ports), ShouldEqual, 1)
		})
	})

	Convey("Given I call a Extract Protocol port list with disjoint port sets", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp", []string{"tcp/80"}, []string{"udp/90"})
		Convey("Then data should be right", func() {
			So(protocols, ShouldBeEmpty)
			So(len(ports), ShouldEqual, 0)
		})
	})

	Convey("Given I call ExtractProtocolsPorts with 20 elements and 1 restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"tcp/80",
				"udp/90:9000",
				"tcp/85",
				"tcp/95:200",
				"rdp",
				"udp/53",
				"icmp",
				"tcp/87",
				"tcp/88",
				"tcp/89",
				"tcp/90",
				"9000",
				"tcp/91",
				"tcp/92",
				"tcp/93",
				"tcp/94",
				"tcp/95",
				"tcp/96",
				"tcp/97",
				"tcp/98",
				"tcp/99",
				"tcp/100",
				"tcp/9090",
				"tcp/9091",
				"tcp/9092",
			},
			[]string{"tcp/80"})

		Convey("Then data should be right", func() {
			So(protocols, ShouldResemble, []string{})
			So(len(ports), ShouldEqual, 1)
			So(ports, ShouldResemble, []string{
				"80",
			})
		})
	})

	Convey("Given I call ExtractProtocolsPorts with 20 elements and same elements in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"tcp/80",
				"udp/90",
				"tcp/85",
				"tcp/200",
				"rdp",
				"udp/53",
				"icmp",
				"tcp/87",
				"tcp/88",
				"tcp/89",
				"tcp/90",
				"9000",
				"tcp/91",
				"tcp/92",
				"tcp/93",
				"tcp/94",
				"tcp/95",
				"tcp/96",
				"tcp/97",
				"tcp/98",
				"tcp/99",
				"tcp/100",
				"tcp/9090",
				"tcp/9091",
				"tcp/9092",
			},
			[]string{
				"tcp/80",
				"udp/90",
				"tcp/85",
				"tcp/200",
				"rdp",
				"udp/53",
				"icmp",
				"tcp/87",
				"tcp/88",
				"tcp/89",
				"tcp/90",
				"9000",
				"tcp/91",
				"tcp/92",
				"tcp/93",
				"tcp/94",
				"tcp/95",
				"tcp/96",
				"tcp/97",
				"tcp/98",
				"tcp/99",
				"tcp/100",
				"tcp/9090",
				"tcp/9091",
				"tcp/9092",
			})

		Convey("Then data should be right", func() {
			So(protocols, ShouldResemble, []string{"ICMP", "RDP"})
			So(len(ports), ShouldEqual, 5)
			So(ports, ShouldResemble,
				[]string{
					"80",
					"85",
					"87:100",
					"200",
					"9090:9092",
				})
		})
	})
}

func Test_ExtractProtocolsPortsWithRange(t *testing.T) {
	Convey("Given I call ExtractProtocolsPorts with 20 elements and same elements in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"tcp/80",
				"udp/90",
				"tcp/85",
				"tcp/200",
				"rdp",
				"udp/53",
				"icmp",
				"tcp/87",
				"tcp/88",
				"tcp/89",
				"tcp/90",
				"9000",
				"tcp/91",
				"tcp/92",
				"tcp/93",
				"tcp/94",
				"tcp/95",
				"tcp/96",
				"tcp/97",
				"tcp/98",
				"tcp/99",
				"tcp/100",
				"tcp/9090",
				"tcp/9091",
				"tcp/9092",
			},
			[]string{
				"tcp/80:100",
				"udp/90",
				"tcp/200",
				"rdp",
				"udp/53",
				"icmp",
				"9000",
				"tcp/9090",
				"tcp/9091",
				"tcp/9092",
			})

		Convey("Then data should be right", func() {
			So(protocols, ShouldResemble, []string{"ICMP", "RDP"})
			So(len(ports), ShouldEqual, 5)
			So(ports, ShouldResemble,
				[]string{
					"80",
					"85",
					"87:100",
					"200",
					"9090:9092",
				})
		})
	})

	Convey("Given I call ExtractProtocolsPorts with overlapping elements and overlapping elements in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"tcp/4:2000",
				"tcp/5:10000",
			},
			[]string{
				"tcp/80:10000",
			})

		Convey("Then data should be right", func() {
			So(protocols, ShouldResemble, []string{})
			So(len(ports), ShouldEqual, 1)
			So(ports, ShouldResemble,
				[]string{
					"80:10000",
				})
		})
	})
}

func Test_ExtractProtocolsPortsWithAny(t *testing.T) {
	Convey("Given I call ExtractProtocolsPorts with valid data and any restricted port", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp", []string{"tcp/80", "udp/90"}, []string{"any"})

		Convey("Then data should be right", func() {
			So(protocols, ShouldBeEmpty)
			So(ports, ShouldContain, "80")
		})
	})

	Convey("Given I call ExtractProtocolsPorts with 20 elements and any restricted port", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"tcp/80",
				"udp/90:9000",
				"tcp/85",
				"tcp/95:200",
				"rdp",
				"udp/53",
				"icmp",
				"tcp/87",
				"tcp/88",
				"tcp/89",
				"tcp/90",
				"9000",
				"tcp/91",
				"tcp/92",
				"tcp/93",
				"tcp/94",
				"tcp/95",
				"tcp/96",
				"tcp/97",
				"tcp/98",
				"tcp/99",
				"tcp/100",
				"tcp/9090",
				"tcp/9091",
				"tcp/9092",
			},
			[]string{"any"},
		)

		Convey("Then data should be right", func() {
			So(protocols, ShouldResemble, []string{"ICMP", "RDP"})
			So(len(ports), ShouldEqual, 4)
			So(ports, ShouldResemble,
				[]string{
					"80",
					"85",
					"87:200",
					"9090:9092",
				})
		})
	})

	Convey("Given I call ExtractProtocolsPorts with any service port and igmp in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("",
			[]string{
				"any",
			},
			[]string{
				"igmp",
			},
		)

		Convey("Then data should be a combined single range", func() {
			So(protocols, ShouldResemble, []string{"IGMP"})
			So(len(ports), ShouldEqual, 0)
			So(ports, ShouldResemble, []string{})
		})
	})

	Convey("Given I call ExtractProtocolsPorts with igmp service port and igmp in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("",
			[]string{
				"igmp",
			},
			[]string{
				"igmp",
			},
		)

		Convey("Then data should be a combined single range", func() {
			So(protocols, ShouldResemble, []string{"IGMP"})
			So(len(ports), ShouldEqual, 0)
			So(ports, ShouldResemble, []string{})
		})
	})

	Convey("Given I call ExtractProtocolsPorts with icmp and any service port and igmp in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("",
			[]string{
				"any",
				"icmp",
			},
			[]string{
				"igmp",
			},
		)

		Convey("Then data should be a combined single range", func() {
			So(protocols, ShouldResemble, []string{"IGMP"})
			So(len(ports), ShouldEqual, 0)
			So(ports, ShouldResemble, []string{})
		})
	})

	Convey("Given I call ExtractProtocolsPorts with 2 non-overlapping elements in service ports and any restricted port", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"tcp/4:2000",
				"tcp/2002:10000",
			},
			[]string{
				"any",
			},
		)

		Convey("Then data should be right", func() {
			So(protocols, ShouldResemble, []string{})
			So(len(ports), ShouldEqual, 2)
			So(ports, ShouldResemble,
				[]string{
					"4:2000",
					"2002:10000",
				},
			)
		})
	})

	Convey("Given I call ExtractProtocolsPorts with 2 non-overlapping elements in service ports and any restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"tcp/4:2000",
				"tcp/2002:10000",
			},
			[]string{
				"any",
				"tcp/4:10000",
			},
		)

		Convey("Then data should be right", func() {
			So(protocols, ShouldResemble, []string{})
			So(len(ports), ShouldEqual, 2)
			So(ports, ShouldResemble,
				[]string{
					"4:2000",
					"2002:10000",
				},
			)
		})
	})

	Convey("Given I call ExtractProtocolsPorts with any service port and 2 non-overlapping elements in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"any",
			},
			[]string{
				"tcp/4:2000",
				"tcp/2002:10000",
			},
		)

		Convey("Then data should be right", func() {
			So(protocols, ShouldResemble, []string{})
			So(len(ports), ShouldEqual, 2)
			So(ports, ShouldResemble,
				[]string{
					"4:2000",
					"2002:10000",
				},
			)
		})
	})

	Convey("Given I call ExtractProtocolsPorts with any service port and 2 non-overlapping elements in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"any",
				"tcp/4:10000",
			},
			[]string{
				"tcp/4:2000",
				"tcp/2002:10000",
			},
		)

		Convey("Then data should be right", func() {
			So(protocols, ShouldResemble, []string{})
			So(len(ports), ShouldEqual, 2)
			So(ports, ShouldResemble,
				[]string{
					"4:2000",
					"2002:10000",
				},
			)
		})
	})

	Convey("Given I call ExtractProtocolsPorts with 2 overlapping elements in service ports and any in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"tcp/4:2000",
				"tcp/5:10000",
			},
			[]string{
				"any",
			},
		)

		Convey("Then data should be a combined single range", func() {
			So(protocols, ShouldResemble, []string{})
			So(len(ports), ShouldEqual, 1)
			So(ports, ShouldResemble,
				[]string{
					"4:10000",
				},
			)
		})
	})

	Convey("Given I call ExtractProtocolsPorts with any service port and 2 overlapping elements in restricted ports", t, func() {
		protocols, ports := ExtractProtocolsPorts("tcp",
			[]string{
				"any",
			},
			[]string{
				"tcp/4:2000",
				"tcp/5:10000",
			},
		)

		Convey("Then data should be a combined single range", func() {
			So(protocols, ShouldResemble, []string{})
			So(len(ports), ShouldEqual, 1)
			So(ports, ShouldResemble,
				[]string{
					"4:10000",
				},
			)
		})
	})
}

func Test_parseServicePort(t *testing.T) {

	type args struct {
		servicePort string
	}

	tests := []struct {
		name         string
		args         args
		wantProtocol string
		wantPorts    string
		wantErr      bool
	}{
		{
			name: "empty protocol and nil servicePorts",
			args: args{
				servicePort: "",
			},
			wantProtocol: "",
			wantPorts:    "",
			wantErr:      true,
		},
		{
			name: "any protocol",
			args: args{
				servicePort: "any",
			},
			wantProtocol: "any",
			wantPorts:    "",
			wantErr:      false,
		},
		{
			name: "proper servicePort",
			args: args{
				servicePort: "tcp/80:8000",
			},
			wantProtocol: "tcp",
			wantPorts:    "80:8000",
			wantErr:      false,
		},
		{
			name: "proper protocols that doesn't support ports ",
			args: args{
				servicePort: "ISIS",
			},
			wantProtocol: "ISIS",
			wantPorts:    "",
			wantErr:      false,
		},
		{
			name: "invalid servicePorts",
			args: args{
				servicePort: "ISISsas",
			},
			wantProtocol: "",
			wantPorts:    "",
			wantErr:      true,
		},
		{
			name: "invalid servicePorts with two /",
			args: args{
				servicePort: "tcp/80/900",
			},
			wantProtocol: "",
			wantPorts:    "",
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProtocol, gotPorts, gotErr := parseServicePort(tt.args.servicePort)
			if gotProtocol != tt.wantProtocol || gotPorts != tt.wantPorts || (gotErr != nil) != tt.wantErr {
				t.Errorf("parseServicePort() = \n Protocol: got %v, want %v \n Ports: got %v, want %v \n Error: got %v, want %v",
					gotProtocol,
					tt.wantProtocol,
					gotPorts,
					tt.wantPorts,
					gotErr,
					tt.wantErr)
			}
		})
	}
}

func TestNewPortSpec(t *testing.T) {
	Convey("When I create a new port spec", t, func() {
		p, err := NewPortSpec(0, 10, "portspec")
		So(err, ShouldBeNil)
		Convey("The correct values must be set", func() {
			So(p, ShouldNotBeNil)
			So(p.Min, ShouldEqual, 0)
			So(p.Max, ShouldEqual, 10)
			So(p.value.(string), ShouldResemble, "portspec")
		})
	})
}

func TestNewPortSpecFromString(t *testing.T) {
	Convey("When I create a valid single port spec from string it should succeed", t, func() {
		p, err := NewPortSpecFromString("10", "string")
		So(err, ShouldBeNil)
		So(p.Min, ShouldEqual, uint16(10))
		So(p.Max, ShouldEqual, uint16(10))
		So(p.value.(string), ShouldResemble, "string")
	})

	Convey("When I create a valid a range  port spec from string it should succeed", t, func() {
		p, err := NewPortSpecFromString("10:20", "string")
		So(err, ShouldBeNil)
		So(p.Min, ShouldEqual, uint16(10))
		So(p.Max, ShouldEqual, uint16(20))
		So(p.value.(string), ShouldResemble, "string")
	})

	Convey("When I create singe port with value greater than 2^16 it shoud fail ", t, func() {
		_, err := NewPortSpecFromString("70000", "string")
		So(err, ShouldNotBeNil)
	})

	Convey("When I create singe port with a negative value it should fail", t, func() {
		_, err := NewPortSpecFromString("-1", "string")
		So(err, ShouldNotBeNil)
	})

	Convey("When I create a range with min > max it shoud fail", t, func() {
		_, err := NewPortSpecFromString("20:10", "string")
		So(err, ShouldNotBeNil)
	})

	Convey("When I create a range with negative min or max  it shoud fail", t, func() {
		_, err := NewPortSpecFromString("-20:10", "string")
		So(err, ShouldNotBeNil)
		_, err = NewPortSpecFromString("-20:-110", "string")
		So(err, ShouldNotBeNil)
	})

	Convey("When I create a range with invalid characters it should fail", t, func() {
		_, err := NewPortSpecFromString("10,20", "string")
		So(err, ShouldNotBeNil)
	})
}

func Test_buildRanges(t *testing.T) {
	type args struct {
		ports []int
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "0 length",
			args: args{
				ports: []int{},
			},
			want: []string{},
		},
		{
			name: "1 length",
			args: args{
				ports: []int{5},
			},
			want: []string{"5"},
		},

		{
			name: "1 continuous range",
			args: args{
				ports: []int{5, 6, 7, 8, 9, 10},
			},
			want: []string{"5:10"},
		},
		{
			name: "n groups close hops",
			args: args{
				ports: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 17, 19},
			},
			want: []string{"1:10", "12:15", "17", "19"},
		},
		{
			name: "n groups",
			args: args{
				ports: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 500, 65533, 65534, 65535},
			},
			want: []string{"1:10", "500", "65533:65535"},
		},
		{
			name: "n groups first not part of sequence",
			args: args{
				ports: []int{1, 4, 5, 6, 7, 8, 9, 10, 500, 65533, 65534, 65535},
			},
			want: []string{"1", "4:10", "500", "65533:65535"},
		},
		{
			name: "n groups last not part of sequence",
			args: args{
				ports: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 500, 65535},
			},
			want: []string{"1:10", "500", "65535"},
		},
		{
			name: "n groups first and last not part of sequence",
			args: args{
				ports: []int{1, 4, 5, 6, 7, 8, 9, 10, 500, 65533, 65535},
			},
			want: []string{"1", "4:10", "500", "65533", "65535"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildRanges(tt.args.ports); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("buildRanges() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimPortRange(t *testing.T) {
	type args struct {
		sports          map[int]struct{}
		filteredPortMap map[int]struct{}
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "Single entry Port map with invalid sport",
			args: args{
				filteredPortMap: map[int]struct{}{
					22: {},
				},
				sports: map[int]struct{}{
					23: {},
				},
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Single entry Port map with range sport",
			args: args{
				filteredPortMap: map[int]struct{}{
					22: {},
				},
				sports: map[int]struct{}{
					1:  {},
					2:  {},
					3:  {},
					4:  {},
					5:  {},
					6:  {},
					7:  {},
					8:  {},
					9:  {},
					10: {},
					11: {},
					12: {},
					13: {},
					14: {},
					15: {},
					16: {},
					17: {},
					18: {},
					19: {},
					20: {},
					21: {},
					22: {},
					23: {},
				},
			},
			want: []string{"22"},
		},
		{
			name: "Single entry Port map with invalid entry",
			args: args{
				filteredPortMap: map[int]struct{}{
					0: {},
				},
				sports: map[int]struct{}{
					1:  {},
					2:  {},
					3:  {},
					4:  {},
					5:  {},
					6:  {},
					7:  {},
					8:  {},
					9:  {},
					10: {},
					11: {},
					12: {},
					13: {},
					14: {},
					15: {},
					16: {},
					17: {},
					18: {},
					19: {},
					20: {},
					21: {},
					22: {},
					23: {},
				},
			},
			want: []string{},
		},
		{
			name: "Empty Port map with sport range",
			args: args{
				filteredPortMap: map[int]struct{}{},
				sports: map[int]struct{}{
					1:  {},
					2:  {},
					3:  {},
					4:  {},
					5:  {},
					6:  {},
					7:  {},
					8:  {},
					9:  {},
					10: {},
					11: {},
					12: {},
					13: {},
					14: {},
					15: {},
					16: {},
					17: {},
					18: {},
					19: {},
					20: {},
					21: {},
					22: {},
					23: {},
				},
			},
			want: []string{},
		},
		{
			name: "One element Port Map with sport range",
			args: args{
				filteredPortMap: map[int]struct{}{
					21: {},
				},
				sports: map[int]struct{}{
					1:  {},
					2:  {},
					3:  {},
					4:  {},
					5:  {},
					6:  {},
					7:  {},
					8:  {},
					9:  {},
					10: {},
					11: {},
					12: {},
					13: {},
					14: {},
					15: {},
					16: {},
					17: {},
					18: {},
					19: {},
					20: {},
					21: {},
					22: {},
					23: {},
				},
			},
			want: []string{"21"},
		},
		{
			name: "Contiguos elements Port Map with sport range",
			args: args{
				filteredPortMap: map[int]struct{}{
					2: {},
					3: {},
					4: {},
				},
				sports: map[int]struct{}{
					1:  {},
					2:  {},
					3:  {},
					4:  {},
					5:  {},
					6:  {},
					7:  {},
					8:  {},
					9:  {},
					10: {},
					11: {},
					12: {},
					13: {},
					14: {},
					15: {},
					16: {},
					17: {},
					18: {},
					19: {},
					20: {},
					21: {},
					22: {},
					23: {},
				},
			},
			want: []string{"2:4"},
		},
		{
			name: "Non contiguous Port Map with sport range",
			args: args{
				filteredPortMap: map[int]struct{}{
					2:  {},
					3:  {},
					4:  {},
					7:  {},
					8:  {},
					10: {},
				},
				sports: map[int]struct{}{
					1:  {},
					2:  {},
					3:  {},
					4:  {},
					5:  {},
					6:  {},
					7:  {},
					8:  {},
					9:  {},
					10: {},
					11: {},
					12: {},
					13: {},
					14: {},
					15: {},
					16: {},
					17: {},
					18: {},
					19: {},
					20: {},
					21: {},
					22: {},
					23: {},
				},
			},
			want: []string{"2:4", "7:8", "10"},
		},
		{
			name: "Null set intersection with Port Map with sport range",
			args: args{
				filteredPortMap: map[int]struct{}{
					50: {},
				},
				sports: map[int]struct{}{
					1: {},
					2: {},
				},
			},
			want: []string{},
		},
		{
			name: "Empty Port map with single sport",
			args: args{
				filteredPortMap: map[int]struct{}{},
				sports: map[int]struct{}{
					50: {},
				},
			},
			want: []string{},
		},
		{
			name: "One element Port Map with single sport",
			args: args{
				filteredPortMap: map[int]struct{}{
					50: {},
				},
				sports: map[int]struct{}{
					50: {},
				},
			},
			want: []string{"50"},
		},
		{
			name: "Contiguos elements Port Map with single sport",
			args: args{
				filteredPortMap: map[int]struct{}{
					48: {},
					49: {},
					50: {},
				},
				sports: map[int]struct{}{
					50: {},
				},
			},
			want: []string{"50"},
		},
		{
			name: "Non contiguous Port Map with single sport",
			args: args{
				filteredPortMap: map[int]struct{}{
					2:  {},
					3:  {},
					4:  {},
					7:  {},
					8:  {},
					10: {},
					50: {},
				},
				sports: map[int]struct{}{
					50: {},
				},
			},
			want: []string{"50"},
		},
		{
			name: "Null set intersection with Port Map with single sport",
			args: args{
				filteredPortMap: map[int]struct{}{
					10: {},
				},
				sports: map[int]struct{}{
					50: {},
				},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TrimPortRange(tt.args.sports, tt.args.filteredPortMap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TrimPortRange() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_intersectedProtocols(t *testing.T) {
	type args struct {
		serviceProtocols    map[string]struct{}
		restrictedProtocols map[string]struct{}
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"Service and restricted protocols match",
			args{
				map[string]struct{}{
					"igmp": {},
				},
				map[string]struct{}{
					"igmp": {},
				},
			},
			[]string{"igmp"},
		},
		{
			"Service and restricted protocols do not match",
			args{
				map[string]struct{}{
					"igmp": {},
				},
				map[string]struct{}{
					"something": {},
				},
			},
			[]string{},
		},
		{
			"1 service protocol and 2 restricted protocols partially overlap",
			args{
				map[string]struct{}{
					"igmp": {},
				},
				map[string]struct{}{
					"igmp":      {},
					"something": {},
				},
			},
			[]string{"igmp"},
		},
		{
			"2 service protocols and 1 restricted protocol partially overlap",
			args{
				map[string]struct{}{
					"igmp":      {},
					"something": {},
				},
				map[string]struct{}{
					"igmp": {},
				},
			},
			[]string{"igmp"},
		},
		{
			"2 service protocols and any restricted protocol",
			args{
				map[string]struct{}{
					"igmp":      {},
					"something": {},
				},
				map[string]struct{}{
					"ANY": {},
				},
			},
			[]string{"igmp", "something"},
		},
		{
			"any service protocol and 2 restricted protocols",
			args{
				map[string]struct{}{
					"ANY": {},
				},
				map[string]struct{}{
					"igmp":      {},
					"something": {},
				},
			},
			[]string{"igmp", "something"},
		},
		{
			"any service protocol and any restricted protocol",
			args{
				map[string]struct{}{
					"ANY": {},
				},
				map[string]struct{}{
					"ANY": {},
				},
			},
			[]string{"ANY"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := intersectedProtocols(tt.args.serviceProtocols, tt.args.restrictedProtocols); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("intersectedProtocols() = %v, want %v", got, tt.want)
			}
		})
	}
}
