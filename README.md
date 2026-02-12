# Project readme <br> 

## Commands to setup virtual environment and install dependencies <br> 
python3 -m venv venv <br> 
source venv/bin/activate      # macOS/Linux <br> 
pip install -r requirements.txt <br> 

## Git and branches <br> 
Naming convention:
{fix/feature}/week-{assignment_number_of_week}/{short_message}

## How to run docker env
### docker compose up --build

## Local testing
### Commands to check functionality

####
    1. you can do docker composition
        docker-compose up --build
        docker composition is set for port 5001! -> http://localhost:5001
    2. do it manually but than don't do step 1
    start a temporary database
        docker run --name my-test-mongo -p 27017:27017 -d mongo:latest
    
    check if docker container is runing
    docker ps
    if not, than start it
        docker start my-test-mongo
    
    download valid dependencies
        go mod tidy
    
    check if it works
        go run main.go
####
