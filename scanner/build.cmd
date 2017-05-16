go get "github.com/hashicorp/go-version"
go get "github.com/oneumyvakin/osext"

set PKGNAME=website-virus-check
set LOCALPATH=%~dp0

mklink /J "%GOPATH%\src\%PKGNAME%" "%LOCALPATH%"

goimports -w "%GOPATH%\src\%PKGNAME%"
go fmt %PKGNAME%
staticcheck %PKGNAME%
go vet %PKGNAME%

set GOOS=windows
set GOARCH=386
go test -v -o "%LOCALPATH%\..\var\test.exe" "%PKGNAME%"

set GOGC=off

set GOOS=linux
set GOARCH=386
go build -o "%LOCALPATH%\..\sbin\website-virus-check.%GOARCH%" %PKGNAME%

set GOOS=windows
go build -o "%LOCALPATH%\..\sbin\website-virus-check.exe" %PKGNAME%

del /Q "%LOCALPATH%/../var/test.exe"
rmdir "%GOPATH%\src\%PKGNAME%"