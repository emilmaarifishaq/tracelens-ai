FROM node:20-alpine

WORKDIR /app

# Install full dependencies (including dev deps: typescript, tailwindcss --
# the build step below needs them even though they won't run at runtime).
COPY package*.json ./
RUN npm install

# Copy everything else and build.
COPY . .
RUN npm run build

EXPOSE 3000

# Health check
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
  CMD node -e "require('http').get('http://localhost:3000', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"

# Start the application
CMD ["npm", "start"]
