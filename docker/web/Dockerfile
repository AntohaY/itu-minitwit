######### COMMENTED OUT CONFIGURATION FOR MINITWIT.PY ###########

# FROM python:3.9-alpine

# WORKDIR /usr/src/app

# ENV DB_IP="dbserver"

# COPY requirements.txt ./
# RUN pip install --no-cache-dir -r requirements.txt

# COPY . .

# CMD [ "python", "./minitwit.py" ]

######### CONFIGURATION FOR GO FILE ###########

# 1. Start with Go
FROM golang:1.25

WORKDIR /usr/src/app

# 2. Copy files
COPY . .

# 3. BUILD the app (This creates a file named 'minitwit-server')
RUN go build -o minitwit-server main.go

# 4. Run the BINARY (Not the text file)
CMD [ "./minitwit-server" ]