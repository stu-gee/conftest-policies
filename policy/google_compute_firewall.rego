package terraform.google_compute_firewall

import data.terraform.util.is_create_or_update
import data.terraform.util.changes_by_type

resource_type := "google_compute_firewall"

deny[msg] {
  changeset := changes_by_type[resource_type][_]
  is_create_or_update(changeset.change.actions)

  changeset.change.after.allow[_].ports[_] == "22"

  msg := sprintf("%v has SSH access allowed", [changeset.address])
}