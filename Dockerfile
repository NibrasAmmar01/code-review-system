FROM node:18-alpine

# Install Chromium for Lighthouse
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont

# Set Chromium path
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser \
    CHROME_BIN=/usr/bin/chromium-browser

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY dist ./dist
COPY templates ./templates
COPY config ./config

# Create reports directory
RUN mkdir -p /app/reports

# Set working directory for reports
VOLUME ["/app/reports"]

# Expose API port
EXPOSE 3000

# Run the application
ENTRYPOINT ["node", "dist/cli/index.js"]
CMD ["--help"]