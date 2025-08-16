FROM node:18-slim

WORKDIR /app

# Install Python and build tools for bcrypt
RUN apt-get update && \
    apt-get install -y python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies (including dev dependencies for building)
RUN npm install --include=dev

# Copy source files
COPY . .

# Build TypeScript
RUN npm run build

# Clean up build tools
RUN apt-get purge -y python3 make g++ && \
    apt-get autoremove -y

# Ensure production dependencies are installed
RUN npm install --omit=dev

CMD ["node", "dist/index.js"]

EXPOSE 3000