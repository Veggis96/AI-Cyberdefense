variable "project_name" {
  description = "Name used for the Docker image and container."
  type        = string
  default     = "ai-cyberdefense-agent"
}

variable "container_command" {
  description = "Command arguments passed to cyberdefense-agent."
  type        = list(string)
  default = [
    "--events",
    "samples/events.jsonl",
    "--memory-db",
    "data/incidents.sqlite",
    "--html-report",
    "reports/report.html",
  ]
}

variable "run_once" {
  description = "Remove the container after it exits."
  type        = bool
  default     = true
}
