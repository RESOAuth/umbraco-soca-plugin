FROM mcr.microsoft.com/dotnet/sdk:10.0.402@sha256:3a48280a9a7c6276c3eeaba1efa6a08820f18c84fb9e6274c187719ecfaf9fbc AS build
WORKDIR /src
COPY . .
RUN dotnet restore tests/RESOAuth.Soca.Umbraco.Tests/RESOAuth.Soca.Umbraco.Tests.csproj --locked-mode
RUN dotnet test tests/RESOAuth.Soca.Umbraco.Tests/RESOAuth.Soca.Umbraco.Tests.csproj --no-restore -c Release
RUN dotnet restore demo/Demo.csproj --locked-mode
RUN dotnet publish demo/Demo.csproj --no-restore -c Release -o /out
FROM mcr.microsoft.com/dotnet/aspnet:10.0.13@sha256:e4b445f93a5deeb6bd7de300febceb8dd7e481ac65ccf1b474eddc3642a3010f
WORKDIR /app
COPY --from=build --chown=app:app /out .
USER root
RUN mkdir -p /app/umbraco/Data /app/umbraco/Logs && chown -R app:app /app
USER app
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "Demo.dll"]
