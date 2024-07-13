// Package libdnstemplate implements a DNS record management client compatible
// with the libdns interfaces for <PROVIDER NAME>. TODO: This package is a
// template only. Customize all godocs for actual implementation.
package libdnsconstellix

import (
	"context"
	"fmt"
	"strconv"
	"net/http"
	"bytes"

	// required by Constellix
	"time"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"

	"github.com/libdns/libdns"
)

// TODO: Providers must not require additional provisioning steps by the callers; it
// should work simply by populating a struct and calling methods on it. If your DNS
// service requires long-lived state or some extra provisioning step, do it implicitly
// when methods are called; sync.Once can help with this, and/or you can use a
// sync.(RW)Mutex in your Provider struct to synchronize implicit provisioning.

type Domain struct {
	ID int `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type DomainRecord struct {
	ID int `json:"id,omitempty"`
	Type string `json:"recordType,omitempty"`
	Name string `json:"name,omitempty"`
	Value []interface{} `json:"value,omitempty"`
	TTL int `json:"ttl,omitempty"`
}

// Provider facilitates DNS record manipulation with <TODO: PROVIDER NAME>.
type Provider struct {
	// TODO: put config fields here (with snake_case json
	// struct tags on exported fields), for example:
	APIKey string `json:"api_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`

	ZoneIDs map[string]int
}

func GetConstellixSecurityToken(api_key string, secret_key string) string {
	cnsst_time := strconv.Itoa(time.Now().UnixMilli())
	cnsst_hmac := hmac.New(sha1.New, []byte(secret_key))
	cnsst_hmac.Write([]byte(cnsst_time))
	cnsst_hmac_b64 := base64.StdEncoding.EncodeToString([]byte(cnsst_hmac))

	return fmt.Sprintf("%s:%s:%s", api_key, cnsst_hmac_b64, cnsst_time)
}

func ConstellixSendRequest(http_method string, api_resource string, api_key string, secret_key string, payload interface{}) (*http.Response, error) {
	api_endpoint := fmt.Sprintf("%s/%s", "https://api.dns.constellix.com", api_resource)

	json_payload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http_method, api_endpoint, bytes.NewReader(json_payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-cns-security-token", GetConstellixSecurityToken(api_key, secret_key))
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode > 299 {
		return nil, fmt.Errorf("Constellix DNS API call failed with HTTP status code %d", res.StatusCode)
	}

	if res.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("Constellix DNS API call returned non-JSON result")
	}

	return res, err
}

func (p *Provider) GetZoneIDMap() map[string]int {
	api_resource := "v1/domains"
	res, err = ConstellixSendRequest("GET", api_resource, p.APIKey, p.SecretKey, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var domains []Domain
	err := json.NewDecoder(res.Body).Decode(&domains)
	if err != nil {
		return nil, err
	}

	zones = make(map[string]int)

	for _, domain := range domains {
		zones[domain.Name] = domain.ID
	}

	return zones
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zone = zone[:len(zone) - 1]

	if p.ZoneIDs[zone] == nil {
		return nil, fmt.Errorf("Zone specified does not exist in Constellix DNS")
	}

	api_resource := fmt.Sprintf("v1/domains/%d/records/txt", p.ZoneIDs[zone])
	res, err = ConstellixSendRequest("GET", api_resource, p.APIKey, p.SecretKey, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var records []DomainRecord
	err := json.NewDecoder(res.Body).Decode(&records)
	if err != nil {
		return nil, err
	}

	libdns_records := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		if record.Type == "TXT" || record.Type == "txt" {
			for _, value := range record.Value {
				libdns_records = append(libdns_records, libdns.Record{
					ID: record.ID,
					Type: record.Type,
					Name: record.Name,
					Value: value.value,
					TTL: record.TTL
				})
			}
		}
	}

	return libdns_records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = zone[:len(zone) - 1]

	if p.ZoneIDs[zone] == nil {
		return nil, fmt.Errorf("Zone specified does not exist in Constellix DNS")
	}

	json_records := make([]DomainRecord, 0, len(records))
	for _, record := range records {
		if record.Type == "TXT" || record.Type == "txt" {
			json_records = append(json_records, DomainRecord{
				Name: record.Name,
				TTL: record.TTL,
				Value: []map[string]string {{"value": record.Value}}
			})
		}
	}

	api_resource := fmt.Sprintf("v1/domains/%d/records/txt", p.ZoneIDs[zone])
	res, err = ConstellixSendRequest("POST", api_resource, p.APIKey, p.SecretKey, json_records)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var rjson_records []DomainRecord
	err := json.NewDecoder(res.Body).Decode(&rjson_records)
	if err != nil {
		return nil, err
	}

	libdns_records := make([]libdns.Record, 0, len(rjson_records))
	for _, record := range rjson_records {
		if record.Type == "TXT" || record.Type == "txt" {
			for _, value := range record.Value {
				libdns_records = append(libdns_records, libdns.Record{
					ID: record.ID,
					Type: record.Type,
					Name: record.Name,
					Value: value.value,
					TTL: record.TTL
				})
			}
		}
	}

	return libdns_records, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = zone[:len(zone) - 1]

	if p.ZoneIDs[zone] == nil {
		return nil, fmt.Errorf("Zone specified does not exist in Constellix DNS")
	}

	libdns_records := make([]libdns.Record, 0, len(records))
	json_records := make([]DomainRecord, 0, len(records))
	for _, record := range records {
		if record.Type == "TXT" || record.Type == "txt" {
			api_resource := fmt.Sprintf("v1/domains/%d/records/txt/%d", p.ZoneIDs[zone], record.ID)
			res, err = ConstellixSendRequest("PUT", api_resource, p.APIKey, p.SecretKey, DomainRecord{
				Name: record.Name,
				TTL: record.TTL,
				Value: []map[string]string {{"value": record.Value}}
			})
			if err != nil {
				return nil, err
			}
			defer res.Body.Close()

			if res.StatusCode == 200 {
				libdns_records = append(libdns_records, record)
			}
		}
	}

	return libdns_records, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = zone[:len(zone) - 1]

	if p.ZoneIDs[zone] == nil {
		return nil, fmt.Errorf("Zone specified does not exist in Constellix DNS")
	}

	libdns_records := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		if record.Type == "TXT" || record.Type == "txt" {
			api_resource := fmt.Sprintf("v1/domains/%d/records/txt/%d", p.ZoneIDs[zone], record.ID)
			res, err = ConstellixSendRequest("DELETE", api_resource, p.APIKey, p.SecretKey, nil)
			if err != nil {
				return nil, err
			}
			defer res.Body.Close()

			if res.StatusCode == 200 {
				libdns_records = append(libdns_records, record)
			}
		}
	}

	return libdns_records, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
