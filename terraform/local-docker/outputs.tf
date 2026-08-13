output "image_name" {
  description = "Built Docker image name."
  value       = docker_image.agent.name
}

output "container_name" {
  description = "Docker container name."
  value       = docker_container.agent.name
}

output "report_path" {
  description = "Expected generated HTML report path on the host."
  value       = "${local.project_root}/reports/report.html"
}
