# Use the official Node.js image as the base image
FROM node:22

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy dependency files first (better for caching)
COPY package*.json ./

# Install the application dependencies
RUN npm install

# Copy the rest of the application files (including tsconfig.json, nest-cli.json, etc.)
COPY . .

# Build the NestJS application
RUN npm run build

# Expose the application port
EXPOSE 3000

# Start the app in production mode
CMD ["npm", "run", "start:prod"]
