# FROM node:18

# WORKDIR /app

# # Copia package.json e instala dependencias
# COPY package*.json ./
# RUN npm install --production

# # Copia todo el backend, incluyendo chat.db
# COPY . .

# # Expone el puerto del backend (si usas 4000 cambia aquí)
# EXPOSE 4000

# CMD ["node", "server.js"]




FROM node:18

WORKDIR /app

# Copia package.json e instala dependencias
COPY package*.json ./
RUN npm install --production

# Copia todo el backend, incluyendo chat.db
COPY . .

# Expone el puerto del backend (si usas 4000 cambia aquí)
EXPOSE 4000

CMD ["node", "server.js"]
