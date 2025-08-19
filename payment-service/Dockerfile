FROM node:18-alpine

WORKDIR /app

# Install dependencies for prom-client
RUN apk add --no-cache python3 make g++

COPY package*.json ./
COPY tsconfig.json ./

RUN npm install --include=dev

COPY . .

RUN npm run build

# Clean up build dependencies
RUN apk del python3 make g++

# Install production dependencies only
RUN npm install --omit=dev

CMD ["node", "dist/index.js"]

EXPOSE 3001