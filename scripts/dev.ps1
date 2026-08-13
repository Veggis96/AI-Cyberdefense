param(
    [ValidateSet("install", "lint", "format", "test", "coverage", "docker-build", "docker-run", "terraform-fmt", "all")]
    [string] $Task = "all"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Task {
    param([string] $Name)

    switch ($Name) {
        "install" {
            python -m pip install -e "$($ProjectRoot)[dev]"
        }
        "lint" {
            python -m ruff check $ProjectRoot
        }
        "format" {
            python -m ruff format $ProjectRoot
        }
        "test" {
            python -m unittest discover -s "$ProjectRoot/tests" -t $ProjectRoot
        }
        "coverage" {
            python -m coverage run -m unittest discover -s "$ProjectRoot/tests" -t $ProjectRoot
            python -m coverage report --show-missing
        }
        "docker-build" {
            docker build -t ai-cyberdefense-agent:local $ProjectRoot
        }
        "docker-run" {
            docker compose --project-directory $ProjectRoot run --rm cyberdefense-agent
        }
        "terraform-fmt" {
            terraform -chdir="$ProjectRoot/terraform/local-docker" fmt -recursive
        }
        "all" {
            Invoke-Task "lint"
            Invoke-Task "test"
        }
    }
}

Invoke-Task $Task
