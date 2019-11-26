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
	Cookie      int `json:"cookie"`
	CookieMask  int `json:"cookie_mask"`
	TableID     int `json:"table_id"`
	IdleTimeout int `json:"idle_timeout"`
	HardTimeout int `json:"hard_timeout"`
	Priority    int `json:"priority"`
	Match       struct {
		InPort  int    `json:"in_port"`
		EthType int    `json:"eth_type"`
		IPv4Src string `json:"ipv4_src"`
	} `json:"match"`
	Actions struct {
		ActionType string `json:"type"`
		Port       int    `json:"port"`
	} `json:"actions"`
}

type SDNControllerPostdstIPJSON struct {
	Dpid        int `json:"dpid"`
	Cookie      int `json:"cookie"`
	CookieMask  int `json:"cookie_mask"`
	TableID     int `json:"table_id"`
	IdleTimeout int `json:"idle_timeout"`
	HardTimeout int `json:"hard_timeout"`
	Priority    int `json:"priority"`
	Match       struct {
		InPort  int    `json:"in_port"`
		EthType int    `json:"eth_type"`
		IPv4Dst string `json:"ipv4_dst"`
	} `json:"match"`
	Actions struct {
		ActionType string `json:"type"`
		Port       int    `json:"port"`
	} `json:"actions"`
}

func createJSONPostObjects(srcIP string, dstIP string) (SDNControllerPostsrcIPJSON, SDNControllerPostdstIPJSON) {
	// SRC json object
	srcJSONStruct := SDNControllerPostsrcIPJSON{
		Dpid:        parsedYamlStruct.Dpid,
		Cookie:      parsedYamlStruct.Details.SrcIPInfo.CookieBase,
		CookieMask:  1,
		TableID:     parsedYamlStruct.TableID,
		IdleTimeout: parsedYamlStruct.IdleTimeout,
		HardTimeout: parsedYamlStruct.HardTimeout,
		Priority:    parsedYamlStruct.Priority}

	srcJSONStruct.Match.InPort = parsedYamlStruct.Details.SrcIPInfo.Matches.InPort
	srcJSONStruct.Match.EthType = parsedYamlStruct.Details.SrcIPInfo.Matches.EthType
	srcJSONStruct.Match.IPv4Src = srcIP

	srcJSONStruct.Actions.ActionType = "OUTPUT"
	srcJSONStruct.Actions.Port = parsedYamlStruct.Details.SrcIPInfo.Actions.OutPort

	// DST json object
	dstJSONStruct := SDNControllerPostdstIPJSON{
		Dpid:        parsedYamlStruct.Dpid,
		Cookie:      parsedYamlStruct.Details.DstIPInfo.CookieBase,
		CookieMask:  1,
		TableID:     parsedYamlStruct.TableID,
		IdleTimeout: parsedYamlStruct.IdleTimeout,
		HardTimeout: parsedYamlStruct.HardTimeout,
		Priority:    parsedYamlStruct.Priority}

	dstJSONStruct.Match.InPort = parsedYamlStruct.Details.DstIPInfo.Matches.InPort
	dstJSONStruct.Match.EthType = parsedYamlStruct.Details.DstIPInfo.Matches.EthType
	dstJSONStruct.Match.IPv4Dst = dstIP

	dstJSONStruct.Actions.ActionType = "OUTPUT"
	dstJSONStruct.Actions.Port = parsedYamlStruct.Details.DstIPInfo.Actions.OutPort

	return srcJSONStruct, dstJSONStruct

}

// required to send two post requests
func sendPOSTRequestToSDNController(srcIP string, dstIP string) {
	srcJSONStruct, dstJSONStruct := createJSONPostObjects(srcIP, dstIP)

	srcJSON, err := json.Marshal(srcJSONStruct)
	if err != nil {
		panic(err)
	}

	dstJSON, err := json.Marshal(dstJSONStruct)
	if err != nil {
		panic(err)
	}

	// Format post requests
	reqSrc, err := http.NewRequest("POST", "http://localhost:8080/DGAHost/serverIP/add", bytes.NewReader(srcJSON))
	reqSrc.Header.Set("Content-Type", "application/json")

	reqDst, err := http.NewRequest("POST", "http://localhost:8080/DGAHost/serverIP/add", bytes.NewReader(dstJSON))
	reqDst.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	responseSrc, err := client.Do(reqSrc)
	if err != nil {
		panic(err)
	}
	defer responseSrc.Body.Close()

	responseDst, err := client.Do(reqDst)
	if err != nil {
		panic(err)
	}
	defer responseDst.Body.Close()
}
