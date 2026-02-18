# Node.js Service Dockerfile
FROM node:20-bullseye

WORKDIR /app

COPY package*.json ./
# Install dependencies
RUN npm install --include=dev

COPY . .

# Copy certificates (Required for Node.js GET requests/Auth)
# Even though Bridge does POSTs, Node might still do some direct GETs or Auth logic
COPY src/certs/*.p12 /app/src/certs/

EXPOSE 3000
ENV PORT=3000

# Start Node.js directly
CMD ["npx", "tsx", "src/index.ts"]
