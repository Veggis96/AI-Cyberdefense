locals {
  project_root = abspath("${path.module}/../..")
}

provider "docker" {}

resource "docker_image" "agent" {
  name = "${var.project_name}:terraform"

  build {
    context = local.project_root
  }
}

resource "docker_container" "agent" {
  name    = var.project_name
  image   = docker_image.agent.image_id
  command = var.container_command

  rm = var.run_once

  volumes {
    host_path      = "${local.project_root}/samples"
    container_path = "/app/samples"
    read_only      = true
  }

  volumes {
    host_path      = "${local.project_root}/data"
    container_path = "/app/data"
  }

  volumes {
    host_path      = "${local.project_root}/reports"
    container_path = "/app/reports"
  }
}
