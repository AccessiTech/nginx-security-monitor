# Running Docker Commands from the Project Root

## Overview

To ensure consistent builds and deployments, all Docker-related commands (including `docker compose` and `docker build`) should be executed from the root directory of the `nginx-security-monitor` project.

## Why Run from the Project Root?

- **Path Consistency:** Docker Compose and Dockerfile paths are resolved relative to the root, avoiding path errors.
- **Build Context:** The build context includes all necessary files and directories for the container.
- **Environment Files:** Environment variables and configuration files are correctly referenced.

## Example Workflow

1. **Navigate to the Project Root:**

   ```sh
   cd /Users/conor/Sites/nginx-security-monitor
   ```

1. **Build the Docker Image:**

   ```sh
   docker compose -f examples/nginx-production/docker-compose.yml build
   ```

1. **Start the Services:**

   ```sh
   docker compose -f examples/nginx-production/docker-compose.yml up -d
   ```

1. **Open an Interactive Shell in the Container:**

   ```sh
   docker exec -it nginx-production-nginx-1 bash
   # Or use 'sh' if bash is not available
   docker exec -it nginx-production-nginx-1 sh
   ```

## Notes

- Always check that you are in the project root before running Docker commands.
- Update paths in `docker-compose.yml` to be relative to the root for CI/CD compatibility.
- If you encounter path errors, verify your working directory and the paths in your compose file.

______________________________________________________________________

For more details, see the `examples/nginx-production/docker-compose.yml` and `examples/nginx-production/Dockerfile` files.
