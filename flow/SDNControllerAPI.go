package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"gopkg.in/yaml.v2"
)

/*
 * Below exist the structures that are needed to extract data from the yaml file
 * The extraction of the yaml file should only occur once
 * JSON objects are created on demand and use information found in this struct
 */
type SrcMatches struct {
	InPort  int    `yaml:"in_port"`
	EthType int    `yaml:"eth_type"`
	IPv4    string `yaml:"ipv4_src"`
}

type DstMatches struct {
	InPort  int    `yaml:"in_port"`
	EthType int    `yaml:"eth_type"`
	IPv4    string `yaml:"ipv4_dst"`
}

type Actions struct {
	OutPort int `yaml:"out_port"`
}

type SrcIPInfo struct {
	CookieBase int        `yaml:"cookie_base"`
	Matches    SrcMatches `yaml:"matches"`
	Actions    Actions    `yaml:"actions"`
}

type DstIPInfo struct {
	CookieBase int        `yaml:"cookie_base"`
	Matches    DstMatches `yaml:"matches"`
	Actions    Actions    `yaml:"actions"`
}

type ParsedYamlStruct struct {
	Dpid        int `yaml:"dpid"`
	HardTimeout int `yaml:"hard_timeout"`
	IdleTimeout int `yaml:"idle_timeout"`
	TableID     int `yaml:"table_id"`
	Priority    int `yaml:"priority"`
	Details     struct {
		SrcIPInfo SrcIPInfo `yaml:"serverIPtoHost"`
		DstIPInfo DstIPInfo `yaml:"hostIPtoServer"`
	} `yaml:"details"`
}

var parsedYamlStruct ParsedYamlStruct

func SDNControllerParseYamlConfig(yamlFilePath string) {
	yamlFile, err := ioutil.ReadFile(yamlFilePath)

	err = yaml.Unmarshal(yamlFile, &parsedYamlStruct)
	if err != nil {
		panic(err)
	}
}

// ! Note: the json keys must be as such, with keys as lowercase
// Note: that marshalling yaml requires to attributes to start with capital letter
// ! Also note you can't pull directly from yaml file as the data needs to be reorganised
type SDNControllerPostsrcIPJSON struct {
	Dpid        int `json:"dpid"`
//	Cookie      int `json:"cookie"`
//	CookieMask  int `json:"cookie_mask"`
	TableID     int `json:"table_id"`
	IdleTimeout int `json:"idle_timeout"`
	HardTimeout int `json:"hard_timeout"`
	Priority    int `json:"priority"`
	Match       struct {
		InPort  int    `json:"in_port"`
		EthType int    `json:"eth_type"`
		IPv4Src string `json:"ipv4_src"`
	} `json:"match"`
	Actions []ActionItem `json:"actions"`
}

type ActionItem struct {
        ActionType string `json:"type"`
        Port       int    `json:"port"`
}

type SDNControllerPostdstIPJSON struct {
	Dpid        int `json:"dpid"`
//	Cookie      int `json:"cookie"`
//	CookieMask  int `json:"cookie_mask"`
	TableID     int `json:"table_id"`
	IdleTimeout int `json:"idle_timeout"`
	HardTimeout int `json:"hard_timeout"`
	Priority    int `json:"priority"`
	Match       struct {
		InPort  int    `json:"in_port"`
		EthType int    `json:"eth_type"`
		IPv4Dst string `json:"ipv4_dst"`
	} `json:"match"`
        Actions [] ActionItem `json:"actions"`
}


func createJSONPostObjects(srcIP string, dstIP string, TTL int) (SDNControllerPostsrcIPJSON, SDNControllerPostdstIPJSON, SDNControllerPostsrcIPJSON, SDNControllerPostdstIPJSON) {
	// SRC json object
	src1JSONStruct := SDNControllerPostsrcIPJSON{
		Dpid:        parsedYamlStruct.Dpid,
//		Cookie:      parsedYamlStruct.Details.SrcIPInfo.CookieBase,
//		CookieMask:  1,
		TableID:     parsedYamlStruct.TableID,
		IdleTimeout: parsedYamlStruct.IdleTimeout,
		HardTimeout: parsedYamlStruct.HardTimeout,
		Priority:    parsedYamlStruct.Priority}

	src1JSONStruct.Match.InPort = parsedYamlStruct.Details.SrcIPInfo.Matches.InPort
	src1JSONStruct.Match.EthType = parsedYamlStruct.Details.SrcIPInfo.Matches.EthType
	src1JSONStruct.Match.IPv4Src = srcIP
	src1JSONStruct.IdleTimeout = TTL

	src1JSONStruct.Actions = append(src1JSONStruct.Actions, ActionItem{ActionType:"OUTPUT", Port: parsedYamlStruct.Details.SrcIPInfo.Actions.OutPort})
	src1JSONStruct.Actions = append(src1JSONStruct.Actions, ActionItem{ActionType:"OUTPUT",Port:7})

	// DST json object
	dst1JSONStruct := SDNControllerPostdstIPJSON{
		Dpid:        parsedYamlStruct.Dpid,
//		Cookie:      parsedYamlStruct.Details.DstIPInfo.CookieBase,
//		CookieMask:  1,
		TableID:     parsedYamlStruct.TableID,
		IdleTimeout: parsedYamlStruct.IdleTimeout,
		HardTimeout: parsedYamlStruct.HardTimeout,
		Priority:    parsedYamlStruct.Priority}

	dst1JSONStruct.Match.InPort = parsedYamlStruct.Details.DstIPInfo.Matches.InPort
	dst1JSONStruct.Match.EthType = parsedYamlStruct.Details.DstIPInfo.Matches.EthType
	dst1JSONStruct.Match.IPv4Dst = dstIP
	dst1JSONStruct.IdleTimeout = TTL

	dst1JSONStruct.Actions = append(dst1JSONStruct.Actions, ActionItem{ActionType:"OUTPUT", Port: parsedYamlStruct.Details.DstIPInfo.Actions.OutPort})
	dst1JSONStruct.Actions = append(dst1JSONStruct.Actions, ActionItem{ActionType:"OUTPUT",Port:8})

//	dstJSONStruct.Actions.ActionType = "OUTPUT"
//	dstJSONStruct.Actions.Port = parsedYamlStruct.Details.DstIPInfo.Actions.OutPort

	src2JSONStruct := SDNControllerPostsrcIPJSON{
		Dpid:        parsedYamlStruct.Dpid,
//		Cookie:      parsedYamlStruct.Details.SrcIPInfo.CookieBase,
//		CookieMask:  1,
		TableID:     parsedYamlStruct.TableID,
		IdleTimeout: parsedYamlStruct.IdleTimeout,
		HardTimeout: parsedYamlStruct.HardTimeout,
		Priority:    parsedYamlStruct.Priority}

	src2JSONStruct.Match.InPort = 9
	src2JSONStruct.Match.EthType = parsedYamlStruct.Details.SrcIPInfo.Matches.EthType
	src2JSONStruct.Match.IPv4Src = srcIP
	src2JSONStruct.IdleTimeout = TTL

	src2JSONStruct.Actions = append(src2JSONStruct.Actions, ActionItem{ActionType:"OUTPUT", Port: parsedYamlStruct.Details.SrcIPInfo.Actions.OutPort})
	src2JSONStruct.Actions = append(src2JSONStruct.Actions, ActionItem{ActionType:"OUTPUT",Port:7})

	// DST json object
	dst2JSONStruct := SDNControllerPostdstIPJSON{
		Dpid:        parsedYamlStruct.Dpid,
//		Cookie:      parsedYamlStruct.Details.DstIPInfo.CookieBase,
//		CookieMask:  1,
		TableID:     parsedYamlStruct.TableID,
		IdleTimeout: parsedYamlStruct.IdleTimeout,
		HardTimeout: parsedYamlStruct.HardTimeout,
		Priority:    parsedYamlStruct.Priority}

	dst2JSONStruct.Match.InPort = 10
	dst2JSONStruct.Match.EthType = parsedYamlStruct.Details.DstIPInfo.Matches.EthType
	dst2JSONStruct.Match.IPv4Dst = dstIP
	dst2JSONStruct.IdleTimeout = TTL

	dst2JSONStruct.Actions = append(dst2JSONStruct.Actions, ActionItem{ActionType:"OUTPUT", Port: parsedYamlStruct.Details.DstIPInfo.Actions.OutPort})
	dst2JSONStruct.Actions = append(dst2JSONStruct.Actions, ActionItem{ActionType:"OUTPUT",Port:8})

//	dstJSONStruct.Actions.ActionType = "OUTPUT"
//	dstJSONStruct.Actions.Port = parsedYamlStruct.Details.DstIPInfo.Actions.OutPort


	return src1JSONStruct, dst1JSONStruct, src2JSONStruct, dst2JSONStruct

}

// required to send two post requests
func sendPOSTRequestToSDNController(srcIP string, dstIP string, TTL int) {
	src1JSONStruct, dst1JSONStruct, src2JSONStruct, dst2JSONStruct := createJSONPostObjects(srcIP, dstIP, TTL)

	src1JSON, err := json.Marshal(src1JSONStruct)
	if err != nil {
		panic(err)
	}

	dst1JSON, err := json.Marshal(dst1JSONStruct)
	if err != nil {
		panic(err)
	}

	src2JSON, err := json.Marshal(src2JSONStruct)
	if err != nil {
		panic(err)
	}

	dst2JSON, err := json.Marshal(dst2JSONStruct)
	if err != nil {
		panic(err)
	}

	// Format post requests
	targetUrl := "http://129.94.5.57:8080/DGAHost/serverIP/add"
//        targetUrl := "http://localhost:8080/DGAHost/serverIP/add"
	reqSrc1, err := http.NewRequest("POST", targetUrl, bytes.NewReader(src1JSON))
	reqSrc1.Header.Set("Content-Type", "application/json")

	reqDst1, err := http.NewRequest("POST", targetUrl, bytes.NewReader(dst1JSON))
	reqDst1.Header.Set("Content-Type", "application/json")

	reqSrc2, err := http.NewRequest("POST", targetUrl, bytes.NewReader(src2JSON))
	reqSrc2.Header.Set("Content-Type", "application/json")

	reqDst2, err := http.NewRequest("POST", targetUrl, bytes.NewReader(dst2JSON))
	reqDst2.Header.Set("Content-Type", "application/json")


	client := &http.Client{}
	responseSrc, err := client.Do(reqSrc1)
	if err != nil {
		panic(err)
	}
	defer responseSrc.Body.Close()

	responseDst, err := client.Do(reqDst1)
	if err != nil {
		panic(err)
	}
	defer responseDst.Body.Close()

        client2 := &http.Client{}
        responseSrc2, err2 := client.Do(reqSrc2)
        if err2 != nil {
                panic(err2)
        }
        defer responseSrc2.Body.Close()

        responseDst2, err2 := client2.Do(reqDst2)
        if err2 != nil {
                panic(err2)
        }
        defer responseDst2.Body.Close()


}

