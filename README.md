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
run this command to connect to database in docker
docker run -d --name my-mongo -p 27017:27017 mongo:latest

run this command to run local environment <br>
go run main.go