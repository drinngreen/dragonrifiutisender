# Stage 1: Build Node.js App
FROM node:20-bullseye as node-builder
WORKDIR /app
COPY package*.json ./
# Use --include=dev to ensure tsx and typescript are installed even if NODE_ENV is production
# Or use 'npm ci' if package-lock is present
RUN npm install --include=dev

COPY . .
# If you have a build step for frontend, uncomment below
# RUN npm run build 

# Stage 2: Build .NET Bridge
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS dotnet-builder
WORKDIR /src
COPY bridge-service/RentriBridgeService.csproj ./bridge-service/
WORKDIR /src/bridge-service
RUN dotnet restore
COPY bridge-service/ .
RUN dotnet publish -c Release -o /app/bridge

# Stage 3: Final Image
FROM node:20-bullseye
WORKDIR /app

# Install .NET Runtime dependencies and Runtime itself
# Microsoft package repository setup for Debian 11 (Bullseye)
RUN apt-get update && \
    apt-get install -y wget && \
    wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y dotnet-runtime-8.0 aspnetcore-runtime-8.0

# Copy Node app (including node_modules with dev deps if needed for tsx)
COPY --from=node-builder /app /app

# Copy Bridge
COPY --from=dotnet-builder /app/bridge /app/bridge-service/bin

# Copy start script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Expose ports (Node + Bridge)
EXPOSE 3000 8765

# Environment variables for Bridge to bind to 0.0.0.0
ENV ASPNETCORE_URLS=http://0.0.0.0:8765

CMD ["./start.sh"]
