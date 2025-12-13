# Install dependencies
FROM node:latest AS install-dependencies

WORKDIR /usr/src/app

COPY package.json package-lock.json ./

# RUN npm install --legacy-peer-deps
RUN npm ci

COPY . .

# Create build
FROM node:latest AS create-build

WORKDIR /usr/src/app

COPY --from=install-dependencies /usr/src/app ./

RUN npm run build

USER node

# Run application
FROM node:latest AS run-application

WORKDIR /usr/src/app

COPY --from=install-dependencies /usr/src/app/node_modules ./node_modules
COPY --from=create-build /usr/src/app/dist ./dist
COPY package.json ./

CMD ["npm", "run", "start:prod"]OPY package.json ./
