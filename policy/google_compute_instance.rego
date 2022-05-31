package terraform.google_compute_instance

import data.terraform.util.is_create_or_update
import data.terraform.util.changes_by_type

resource_type := "google_compute_instance"

allowed_environments := [
  "sandbox",
  "development",
  "qa",
  "pvs",
  "slabeling",
  "production",
]

required_labels := {
  "billing", 
  "dept", 
  "environment"
}

allowed_zones := [
  "us-central1-b",
  "us-central1-c"
]

deny[msg] {
  changeset := changes_by_type[resource_type][_]
  is_create_or_update(changeset.change.actions)

  changeset.change.after.name != "test-instance-1"

  msg := sprintf("%v has name other than default", [changeset.address])
}

# Missing required labels
deny[msg] {
  changeset := changes_by_type[resource_type][_]
  split(changeset.address, ".")[0] != "data"

  provided_labels := {label | changeset.change.after.labels[label]}
  missing_labels := required_labels - provided_labels

  count(missing_labels) > 0

  msg := sprintf("%v is missing required labels: %v", [
    changeset.address,
    concat(", ", missing_labels),
  ])
}

# Invalid environment label
deny[msg] {
  changeset := changes_by_type[resource_type][_]

  not valid_label(changeset.change.after.labels.environment, allowed_environments)
  msg := sprintf("%v has an invalid environment label: [ %v ]. Allowed environment labels: [ %v ]", [
    changeset.address,
    changeset.change.after.labels.environment,
    concat(", ", allowed_environments)
  ])
}

valid_label(label, values) {
  label == values[_]
}

# Invalid zone
deny[msg] {
  changeset := changes_by_type[resource_type][_]

  not valid_zone(changeset.change.after.zone, allowed_zones)
  msg := sprintf("%v is in an invalid zone: [ %v ]. Allowed zones: [ %v ]", [
    changeset.address,
    changeset.change.after.zone,
    concat(", ", allowed_zones)
  ])
}

valid_zone(zone, values) {
  zone == values[_]
}

# Zone not set
deny[msg] {
  changeset := changes_by_type[resource_type][_]

  not has_key(changeset.change.after, "zone")
  
  msg := sprintf("%v doesn't have zone set. Allowed zones: [ %v ]", [
    changeset.address,
    concat(", ", allowed_zones)
  ])
}

has_key(x, k) { 
	_ = x[k]
}