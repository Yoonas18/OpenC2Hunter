FROM node:20-alpine AS build
WORKDIR /app
ARG VITE_OPENC2_TOKEN=""
ARG VITE_DEMO_MODE="false"
ENV VITE_OPENC2_TOKEN=$VITE_OPENC2_TOKEN
ENV VITE_DEMO_MODE=$VITE_DEMO_MODE
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
