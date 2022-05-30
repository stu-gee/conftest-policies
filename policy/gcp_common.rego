package terraform.gcp.common

import data.terraform.util.contains_resource
import data.terraform.util.resources
import data.terraform.util.tfplan_resources

required_resources := [
]

denied_resources := [
]

# Using a denied resource
deny[msg] {
  some i
  contains_resource(denied_resources[i])
  rs := resources(denied_resources[i])

  msg := sprintf("%v invalid, cannot use resource type %v", [
    rs[_].address,
    denied_resources[_]
  ])
}

# Provider must start with "registry.terraform.io/hashicorp/*"
deny[msg] {
  p := split(providers[_], "/")
  p[0] != "registry.terraform.io"

  count(p) > 0

  msg := sprintf("Must use providers from registry.terraform.io: %v", [p])
}

deny[msg] {
  p := split(providers[_], "/")
  p[1] != "hashicorp"

  count(p) > 0

  msg := sprintf("Must use providers from hashicorp: %v", [p])
}

providers = {rs[i].address: rs[i].provider_name |
  some path, value
  walk(input, [path, value])
  rs := tfplan_resources(path, value)
}

# Missing required resource
deny[msg] {
  some i
  not contains_resource(required_resources[i])

  msg := sprintf("Missing required resource %v", [
    required_resources[i]
  ])
}

# Non-module/data objects
deny[msg] {
  changeset := input.resource_changes[_]
  changeset.provider_name == "registry.terraform.io/hashicorp/aws"

  split(changeset.address, ".")[0] != "module"
  split(changeset.address, ".")[0] != "data"
  changeset.mode == "managed"

  msg := sprintf("%v is not a module", [changeset.address])
}


