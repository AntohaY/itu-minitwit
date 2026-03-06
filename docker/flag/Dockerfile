FROM mcr.microsoft.com/dotnet/core/runtime:3.1 AS base
WORKDIR /app

# BUILD
FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
WORKDIR /build
# Assuming your source code is inside a flag_tool folder in your repo
COPY /flag_tool .
RUN dotnet restore "flag_tool.csproj"
RUN dotnet build "flag_tool.csproj" -c Release -o /app

# COMPILE
FROM build AS publish
# This securely compiles the app directly into the /app directory
RUN dotnet publish "flag_tool.csproj" -c Release -o /app

# RUNTIME
FROM base AS final
WORKDIR /app
COPY --from=publish /app .

# Keep bash as the command, but we will configure docker-compose
# to keep it awake so you can actually use it!
CMD ["/bin/bash"]