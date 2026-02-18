# Stage 1: Build Node.js App
FROM node:20-bullseye as node-builder
WORKDIR /app
COPY package*.json ./
# Install dependencies including concurrently
RUN npm install --include=dev

COPY . .

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
RUN apt-get update && \
    apt-get install -y wget && \
    wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y dotnet-runtime-8.0 aspnetcore-runtime-8.0

# Install tsx globally
RUN npm install -g tsx

# Copy Node app
COPY --from=node-builder /app /app

# Copy Bridge
COPY --from=dotnet-builder /app/bridge /app/bridge-service/bin

# *** CRITICAL: Copy Certificates directly during build ***
# This ensures they exist where the bridge expects them
COPY src/certs/*.p12 /app/bridge-service/bin/

# Expose ports (Node + Bridge)
EXPOSE 3000 8765

# Environment variables
ENV ASPNETCORE_URLS=http://0.0.0.0:8765
ENV PORT=3000

# Start both services using concurrently defined in package.json
CMD ["npm", "start"]
