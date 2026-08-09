package state

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestReleaseDefinitionsExposeTheCompleteDeterministicSchemaOneAndNoInventedMigration(t *testing.T) {
	first, err := ReleaseDefinitions()
	second, secondErr := ReleaseDefinitions()
	if err != nil || secondErr != nil || len(first) != 1 || !bytes.Equal(first["desired-state-v1.schema.json"], second["desired-state-v1.schema.json"]) {
		t.Fatalf("release definitions = %v, %v, %v", first, err, secondErr)
	}
	var schema releaseSchema
	if json.Unmarshal(first["desired-state-v1.schema.json"], &schema) != nil || schema.Draft != "https://json-schema.org/draft/2020-12/schema" || schema.Type != "object" || schema.AdditionalProperties == nil || *schema.AdditionalProperties || len(schema.Properties) != 6 {
		t.Fatalf("schema envelope = %#v", schema)
	}
	payload := schema.Properties["payload"]
	profiles := payload.Properties["connection_profiles"]
	if len(payload.Properties) != 7 || len(payload.Required) != 7 || len(profiles.Properties) != 6 || len(profiles.Required) != 6 {
		t.Fatalf("schema payload = %#v", payload)
	}
	for name, property := range payload.Properties {
		if property.Type != "object" || property.AdditionalProperties == nil || *property.AdditionalProperties || len(property.Properties) == 0 {
			t.Fatalf("incomplete %s schema = %#v", name, property)
		}
	}
}
