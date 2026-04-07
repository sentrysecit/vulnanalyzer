#!/bin/bash
set -e

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Verificar dependencias
for cmd in pip git docker; do
    if ! command_exists $cmd; then
        echo "Error: $cmd is not installed"
        exit 1
    fi
done

# Verificar Docker daemon
if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker daemon is not running"
    exit 1
fi

# Verificar requirements.txt
if [ ! -f "requirements.txt" ]; then
    echo "Error: requirements.txt not found"
    exit 1
fi

# Instalar dependencias
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Configurar Caldera
mkdir -p tools
cd tools

if [ -d "caldera" ]; then
    echo "Removing existing Caldera directory..."
    rm -rf caldera
fi

echo "Cloning Caldera repository..."
git clone https://github.com/mitre/caldera.git --recursive --branch 5.3.0
cd caldera

echo "Building Docker image..."
docker build --build-arg WIN_BUILD=true . -t caldera:server

echo "Setup completed successfully!"
echo "Correr caldera con el docker-compose.yml"
# echo "Run Caldera with: docker run -p 8888:8888 caldera:server"

# Descargar OpenVAS (opcional)
# echo "Downloading OpenVAS image..."
# docker pull immauss/openvas:24.12.03